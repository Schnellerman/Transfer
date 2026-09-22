// wpscan-rs
//
// Внешний (HTTP-only) скан большого списка доменов в 2 фазы:
//
//   Фаза 1: детект WordPress по набору независимых сигнатур
//           (обычный HTML/meta, /wp-json/, alt REST route, /wp-login.php,
//           /wp-admin/ редирект, /xmlrpc.php, /readme.html, /feed/).
//           Сетевая ошибка (TLS/DNS/timeout) помечается отдельно
//           от "признаков WP не нашёл" — это разные вещи, и их
//           нельзя схлопывать в один статус, иначе занижаешь охват.
//
//   Фаза 2: только для доменов, где WP подтверждён — проверка плагина
//           "Partial Shipment for WooCommerce" (slug: wc-partial-shipment)
//           и его версии на CVE-2026-9858 (Missing Authorization, <= 3.4).
//
// Использование:
//   wpscan-rs -i list.txt -o results.csv -c 50 --timeout 8
//
// list.txt: один домен/URL на строку, https:// не обязателен.

use clap::Parser;
use futures::stream::{self, StreamExt};
use regex::Regex;
use reqwest::{Client, Response, StatusCode};
use serde::Serialize;
use std::fs;
use std::time::Duration;

const PLUGIN_SLUG: &str = "wc-partial-shipment";
const VULNERABLE_MAX_VERSION: &str = "3.4";

#[derive(Parser, Debug)]
#[command(name = "wpscan-rs", about = "External WordPress + CVE-2026-9858 perimeter scanner")]
struct Args {
    /// Файл со списком доменов, по одному на строку
    #[arg(short, long)]
    input: String,

    /// Куда сохранить CSV с результатами
    #[arg(short, long, default_value = "results.csv")]
    output: String,

    /// Число одновременных запросов. Каждый домен внутри делает до 7-8
    /// последовательных HTTP-запросов (сигналы WP), так что при -c 50
    /// одновременно может быть открыто 300+ соединений — на части сетей/прокси
    /// это приводит к connection reset и ложным "все запросы упали".
    /// Если ловишь массовые unreachable — снижай это значение, не таймаут.
    #[arg(short, long, default_value_t = 25)]
    concurrency: usize,

    /// Таймаут одного запроса, сек
    #[arg(long, default_value_t = 8)]
    timeout: u64,

    /// User-Agent (важно оставить опознаваемым для WAF/логов)
    #[arg(long, default_value = "Mozilla/5.0 (compatible; wpscan-rs/0.3; +internal-security-audit)")]
    user_agent: String,
}

#[derive(Debug, Serialize)]
struct Row {
    domain: String,
    scheme_used: String,
    is_wordpress: bool,
    wp_detection: String,
    plugin_status: String,
    plugin_version: String,
    cve_2026_9858_vulnerable: bool,
}

/// Возвращает кандидатов схемы: если домен без схемы — пробуем https, потом http.
/// Если схема уже указана явно пользователем — используем только её.
fn scheme_candidates(raw: &str) -> Vec<String> {
    let raw = raw.trim().trim_end_matches('/');
    if raw.starts_with("http://") || raw.starts_with("https://") {
        vec![raw.to_string()]
    } else {
        vec![format!("https://{}", raw), format!("http://{}", raw)]
    }
}

fn version_lte(ver: &str, max_vulnerable: &str) -> Option<bool> {
    let parse = |s: &str| -> Option<Vec<u32>> {
        s.trim().split('.').map(|p| p.parse::<u32>().ok()).collect()
    };
    let v = parse(ver)?;
    let m = parse(max_vulnerable)?;
    let len = v.len().max(m.len());
    for i in 0..len {
        let a = *v.get(i).unwrap_or(&0);
        let b = *m.get(i).unwrap_or(&0);
        if a < b {
            return Some(true);
        }
        if a > b {
            return Some(false);
        }
    }
    Some(true)
}

async fn get(client: &Client, url: &str) -> Result<Response, String> {
    client.get(url).send().await.map_err(|e| {
        if e.is_timeout() {
            format!("timeout: {}", e)
        } else if e.is_connect() {
            format!("connect error: {}", e)
        } else {
            format!("{}", e)
        }
    })
}

/// Обёртка вокруг get(), которая параллельно пишет реальную причину ошибки
/// в last_error и взводит reached=true при любом успешном ответе (даже 403/404 —
/// это всё равно значит "сервер ответил", в отличие от timeout/connect error).
async fn probe(client: &Client, url: &str, last_error: &mut String, reached: &mut bool) -> Option<Response> {
    match get(client, url).await {
        Ok(resp) => {
            *reached = true;
            Some(resp)
        }
        Err(e) => {
            *last_error = format!("{} ({})", e, url);
            None
        }
    }
}

/// Клиенты для двух режимов: обычный (следует редиректам — нужен почти
/// везде, т.к. сайты редиректят http->https и domain->www) и no-redirect
/// (нужен только для одной проверки: смотрим сам Location у /wp-admin/,
/// который почти всегда указывает на wp-login.php).
struct Clients {
    follow: Client,
    no_redirect: Client,
}

struct WpDetection {
    is_wp: bool,
    // true = сигнатуру не нашли ни на одном пути, false = не смогли проверить (сеть)
    reachable: bool,
    method: String,
}

/// Многосигнальный детект. Порядок — от дешёвого/надёжного к более редкому.
/// Останавливается на первом сработавшем сигнале.
async fn detect_wordpress(clients: &Clients, base: &str) -> WpDetection {
    let client = &clients.follow;
    let generator_re = Regex::new(r#"(?i)<meta\s+name=["']generator["']\s+content=["']WordPress"#).unwrap();
    let mut any_request_succeeded = false;
    let mut last_error = String::new();

    // 1) Главная страница: meta generator, wp-content/wp-includes в HTML, Link-заголовок на wp-json.
    if let Some(resp) = probe(client, base, &mut last_error, &mut any_request_succeeded).await {
        let link_hit = resp
            .headers()
            .get("link")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.contains("wp-json"))
            .unwrap_or(false);

        if let Ok(body) = resp.text().await {
            if generator_re.is_match(&body) {
                return WpDetection { is_wp: true, reachable: true, method: "meta generator".into() };
            }
            if body.contains("/wp-content/") || body.contains("/wp-includes/") {
                return WpDetection { is_wp: true, reachable: true, method: "wp-content/wp-includes в HTML".into() };
            }
            if link_hit {
                return WpDetection { is_wp: true, reachable: true, method: "Link header -> wp-json".into() };
            }
        } else if link_hit {
            return WpDetection { is_wp: true, reachable: true, method: "Link header -> wp-json".into() };
        }
    }

    // 2) /wp-json/ — REST API, обычный путь.
    if let Some(resp) = probe(client, &format!("{}/wp-json/", base), &mut last_error, &mut any_request_succeeded).await {
        if resp.status() == StatusCode::OK {
            if let Ok(body) = resp.text().await {
                if body.contains("wp/v2") || body.contains("\"namespaces\"") {
                    return WpDetection { is_wp: true, reachable: true, method: "/wp-json/".into() };
                }
            }
        }
    }

    // 2b) Альтернативный REST route — работает даже если pretty permalinks
    //     выключены и /wp-json/ отдаёт 404. Это как раз то, что часто
    //     ловит feroxbuster, а прямой /wp-json/ — нет.
    if let Some(resp) = probe(client, &format!("{}/?rest_route=/", base), &mut last_error, &mut any_request_succeeded).await {
        if resp.status() == StatusCode::OK {
            if let Ok(body) = resp.text().await {
                if body.contains("wp/v2") || body.contains("\"namespaces\"") {
                    return WpDetection { is_wp: true, reachable: true, method: "?rest_route=/ (permalinks off)".into() };
                }
            }
        }
    }

    // 3) /xmlrpc.php — классическая сигнатура, почти никогда не выключена.
    //    GET на него отдаёт характерный текст даже без авторизации.
    if let Some(resp) = probe(client, &format!("{}/xmlrpc.php", base), &mut last_error, &mut any_request_succeeded).await {
        if let Ok(body) = resp.text().await {
            if body.contains("XML-RPC server accepts POST requests only")
                || body.contains("XML-RPC")
            {
                return WpDetection { is_wp: true, reachable: true, method: "/xmlrpc.php".into() };
            }
        }
    }

    // 4) /wp-login.php — прямой контент или характерный редирект.
    if let Some(resp) = probe(client, &format!("{}/wp-login.php", base), &mut last_error, &mut any_request_succeeded).await {
        if resp.status().is_success() || resp.status() == StatusCode::FORBIDDEN {
            if let Ok(body) = resp.text().await {
                let lower = body.to_lowercase();
                if lower.contains("wordpress") || lower.contains("wp-submit") {
                    return WpDetection { is_wp: true, reachable: true, method: "/wp-login.php".into() };
                }
            }
        }
    }

    // 5) /wp-admin/ без авторизации почти всегда редиректит на wp-login.php
    //    с ?redirect_to= — сигнал даже если сам wp-login.php вернул что-то нетипичное.
    //    Важно: используем клиент БЕЗ автоследования редиректам, иначе
    //    reqwest сам уйдёт на wp-login.php и мы получим 200 с другим URL,
    //    а не Location-заголовок, который нам тут и нужен.
    if let Some(resp) = probe(&clients.no_redirect, &format!("{}/wp-admin/", base), &mut last_error, &mut any_request_succeeded).await {
        let location = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        if location.contains("wp-login.php") {
            return WpDetection { is_wp: true, reachable: true, method: "/wp-admin/ -> редирект на wp-login.php".into() };
        }
    }

    // 6) /feed/ — RSS почти всегда содержит generator тег с wordpress.org.
    if let Some(resp) = probe(client, &format!("{}/feed/", base), &mut last_error, &mut any_request_succeeded).await {
        if resp.status() == StatusCode::OK {
            if let Ok(body) = resp.text().await {
                if body.to_lowercase().contains("wordpress.org") {
                    return WpDetection { is_wp: true, reachable: true, method: "/feed/ generator".into() };
                }
            }
        }
    }

    // 7) /readme.html в корне — дефолтный файл ядра, часто забывают удалить.
    if let Some(resp) = probe(client, &format!("{}/readme.html", base), &mut last_error, &mut any_request_succeeded).await {
        if resp.status() == StatusCode::OK {
            if let Ok(body) = resp.text().await {
                if body.to_lowercase().contains("wordpress") {
                    return WpDetection { is_wp: true, reachable: true, method: "/readme.html".into() };
                }
            }
        }
    }

    if !any_request_succeeded {
        return WpDetection { is_wp: false, reachable: false, method: format!("все запросы упали: {}", last_error) };
    }

    WpDetection { is_wp: false, reachable: true, method: "ни один из сигналов не сработал".into() }
}

struct PluginCheck {
    status: String,
    version: String,
    vulnerable: bool,
}

async fn check_plugin(client: &Client, base: &str) -> PluginCheck {
    let readme_re = Regex::new(r"(?i)stable tag:\s*([0-9]+(?:\.[0-9]+){0,2})").unwrap();

    let readme_url = format!("{}/wp-content/plugins/{}/readme.txt", base, PLUGIN_SLUG);
    if let Ok(resp) = get(client, &readme_url).await {
        if resp.status() == StatusCode::OK {
            if let Ok(body) = resp.text().await {
                if body.to_lowercase().contains("partial shipment") || readme_re.is_match(&body) {
                    if let Some(cap) = readme_re.captures(&body) {
                        let ver = cap[1].to_string();
                        let vulnerable = version_lte(&ver, VULNERABLE_MAX_VERSION).unwrap_or(false);
                        return PluginCheck { status: "found_readme".into(), version: ver, vulnerable };
                    }
                    return PluginCheck {
                        status: "found_readme_no_version".into(),
                        version: "unknown".into(),
                        vulnerable: false,
                    };
                }
            }
        }
    }

    let candidate_pages = [
        base.to_string(),
        format!("{}/my-account/orders/", base),
        format!("{}/checkout/", base),
        format!("{}/shop/", base),
    ];

    for page in candidate_pages.iter() {
        if let Ok(resp) = get(client, page).await {
            if let Ok(body) = resp.text().await {
                if body.contains(PLUGIN_SLUG) {
                    return PluginCheck {
                        status: "suspected_from_html_no_version".into(),
                        version: "unknown".into(),
                        vulnerable: false,
                    };
                }
            }
        }
    }

    PluginCheck { status: "not_found".into(), version: "".into(), vulnerable: false }
}

async fn scan_domain(clients: &Clients, raw_domain: &str) -> Row {
    let candidates = scheme_candidates(raw_domain);
    let mut last_unreachable_method = String::new();

    for base in candidates {
        let wp = detect_wordpress(clients, &base).await;

        if wp.is_wp {
            let plugin = check_plugin(&clients.follow, &base).await;
            return Row {
                domain: raw_domain.to_string(),
                scheme_used: base,
                is_wordpress: true,
                wp_detection: wp.method,
                plugin_status: plugin.status,
                plugin_version: plugin.version,
                cve_2026_9858_vulnerable: plugin.vulnerable,
            };
        }

        if wp.reachable {
            // Домен ответил, но признаков WP нет — дальше пробовать другую схему
            // для того же хоста почти бессмысленно, фиксируем результат сразу.
            return Row {
                domain: raw_domain.to_string(),
                scheme_used: base,
                is_wordpress: false,
                wp_detection: wp.method,
                plugin_status: "skipped_not_wp".into(),
                plugin_version: "".into(),
                cve_2026_9858_vulnerable: false,
            };
        }

        // Не достучались по этой схеме — пробуем следующую (https -> http).
        last_unreachable_method = wp.method;
    }

    Row {
        domain: raw_domain.to_string(),
        scheme_used: "".into(),
        is_wordpress: false,
        wp_detection: format!("UNREACHABLE: {}", last_unreachable_method),
        plugin_status: "skipped_unreachable".into(),
        plugin_version: "".into(),
        cve_2026_9858_vulnerable: false,
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let content = fs::read_to_string(&args.input)?;
    let domains: Vec<String> = content
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();

    println!("Загружено доменов: {}", domains.len());

    let follow_client = Client::builder()
        .timeout(Duration::from_secs(args.timeout))
        .user_agent(args.user_agent.clone())
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()?;

    let no_redirect_client = Client::builder()
        .timeout(Duration::from_secs(args.timeout))
        .user_agent(args.user_agent.clone())
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let clients = std::sync::Arc::new(Clients {
        follow: follow_client,
        no_redirect: no_redirect_client,
    });

    let results: Vec<Row> = stream::iter(domains.into_iter())
        .map(|d| {
            let clients = clients.clone();
            async move { scan_domain(&clients, &d).await }
        })
        .buffer_unordered(args.concurrency)
        .collect()
        .await;

    let mut wtr = csv::Writer::from_path(&args.output)?;
    for row in &results {
        wtr.serialize(row)?;
        println!(
            "{:<35} wp={:<5} [{}]  plugin={:<28} ver={:<10} vuln={}",
            row.domain, row.is_wordpress, row.wp_detection, row.plugin_status, row.plugin_version, row.cve_2026_9858_vulnerable
        );
    }
    wtr.flush()?;

    let total = results.len();
    let wp_count = results.iter().filter(|r| r.is_wordpress).count();
    let vulnerable = results.iter().filter(|r| r.cve_2026_9858_vulnerable).count();
    let suspected = results.iter().filter(|r| r.plugin_status == "suspected_from_html_no_version").count();
    let unreachable = results.iter().filter(|r| r.plugin_status == "skipped_unreachable").count();

    println!(
        "\nИтого: {} доменов. WordPress найден на {}. Уязвимо к CVE-2026-9858: {}. На ручную проверку (плагин виден, версия нет): {}. Недоступно/сетевая ошибка: {} (их надо перепроверить отдельно, это НЕ 'не WP').\nПолный отчёт: {}",
        total, wp_count, vulnerable, suspected, unreachable, args.output
    );

    Ok(())
}
