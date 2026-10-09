//! Passive WordPress version checker for CVE-2026-93485 ("Comment2Shell").
//!
//! This tool ONLY reads version information that a WordPress site exposes to any
//! visitor (meta generator tag, /feed/ generator, /wp-includes/version.php,
//! /wp-json/). It does NOT send comments, payloads, or exploit anything.
//! Run it only against hosts you are authorized to assess.
//!
//! Vulnerability: stored XSS -> RCE in WordPress core, versions 4.7 .. 7.1.0.
//! Fixed in 7.1.1 (with security backports on each branch, e.g. 7.0.5, 6.9.8,
//! down to 4.7.36). Because of backports, "version < 7.1.1" is NOT a valid
//! verdict on its own — we compare against the fixed version of the same branch.
//!
//! Usage:
//!   cargo run --release -- domains.txt
//!   (one domain per line; blank lines and lines starting with # are ignored)
//!
//! Output: CSV to stdout -> domain,wp_detected,version,source,status

use futures::stream::{self, StreamExt};
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;
use std::time::Duration;

const CONCURRENCY: usize = 15;
const TIMEOUT_SECS: u64 = 12;
const UA: &str = "wp-version-check/0.1 (authorized security assessment)";

// --- Fixed version per WordPress branch (major.minor -> fixed patch) ---------
// Main branches confirmed from the 7.1.1 advisory. Older branches down to 4.7
// also received backports (…, 4.7.36). Fill these in from the WordPress release
// notes for a fully precise verdict on legacy installs; until then, an affected
// legacy branch is reported as VERIFY_BACKPORT rather than guessed.
static FIXED: Lazy<HashMap<(u32, u32), (u32, u32, u32)>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert((7, 1), (7, 1, 1));
    m.insert((7, 0), (7, 0, 5));
    m.insert((6, 9), (6, 9, 8));
    // Example of how to extend with backports once you pull the full list:
    // m.insert((6, 8), (6, 8, X));
    // ...
    // m.insert((4, 7), (4, 7, 36));
    m
});

// First affected branch. Anything below 4.7 predates the vulnerable code path.
const FIRST_AFFECTED: (u32, u32, u32) = (4, 7, 0);

type Ver = (u32, u32, u32);

fn parse_ver(s: &str) -> Option<Ver> {
    let mut it = s.trim().split('.');
    let major = it.next()?.parse().ok()?;
    let minor = it.next().unwrap_or("0").parse().ok()?;
    let patch = it.next().unwrap_or("0").parse().ok()?;
    Some((major, minor, patch))
}

fn classify(v: Ver) -> &'static str {
    if v < FIRST_AFFECTED {
        return "NOT_AFFECTED";
    }
    match FIXED.get(&(v.0, v.1)) {
        Some(&fixed) => {
            if v < fixed {
                "VULNERABLE"
            } else {
                "PATCHED"
            }
        }
        // Branch is in the affected range but we don't have its fixed patch
        // version hardcoded — don't guess.
        None => "VERIFY_BACKPORT",
    }
}

// --- Version extractors ------------------------------------------------------
static RE_VERSION_PHP: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"\$wp_version\s*=\s*'([0-9]+(?:\.[0-9]+){1,2})'"#).unwrap());
static RE_GENERATOR: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"WordPress\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)"#).unwrap());
static RE_FEED_VER: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"wordpress\.org/\?v=([0-9]+\.[0-9]+(?:\.[0-9]+)?)"#).unwrap());

struct Record {
    domain: String,
    wp_detected: bool,
    version: Option<String>,
    source: &'static str,
    status: String,
}

async fn fetch(client: &reqwest::Client, url: &str) -> Option<String> {
    let resp = client.get(url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    // cap body size to avoid pulling huge pages
    resp.text().await.ok().map(|b| b.chars().take(500_000).collect())
}

async fn check(client: reqwest::Client, domain: String) -> Record {
    // Normalize to a base URL; try https first, http as fallback for reachability.
    let bases: Vec<String> = if domain.starts_with("http://") || domain.starts_with("https://") {
        vec![domain.clone()]
    } else {
        vec![format!("https://{domain}"), format!("http://{domain}")]
    };

    let mut wp_detected = false;
    let mut reachable = false;

    for base in &bases {
        let base = base.trim_end_matches('/');

        // 1) version.php — most authoritative, usually blocked (403) but worth a shot.
        if let Some(body) = fetch(&client, &format!("{base}/wp-includes/version.php")).await {
            reachable = true;
            if let Some(c) = RE_VERSION_PHP.captures(&body) {
                let v = c[1].to_string();
                let status = parse_ver(&v).map(classify).unwrap_or("UNKNOWN_VERSION").to_string();
                return Record { domain, wp_detected: true, version: Some(v), source: "version.php", status };
            }
        }

        // 2) homepage -> <meta name="generator" content="WordPress X.Y">
        if let Some(body) = fetch(&client, base).await {
            reachable = true;
            if body.contains("/wp-content/") || body.contains("/wp-includes/") {
                wp_detected = true;
            }
            for line in body.lines().filter(|l| l.contains("generator")) {
                if let Some(c) = RE_GENERATOR.captures(line) {
                    wp_detected = true;
                    let v = c[1].to_string();
                    let status = parse_ver(&v).map(classify).unwrap_or("UNKNOWN_VERSION").to_string();
                    return Record { domain, wp_detected: true, version: Some(v), source: "meta-generator", status };
                }
            }
        }

        // 3) RSS feed -> <generator>https://wordpress.org/?v=X.Y</generator>
        if let Some(body) = fetch(&client, &format!("{base}/feed/")).await {
            reachable = true;
            if let Some(c) = RE_FEED_VER.captures(&body) {
                wp_detected = true;
                let v = c[1].to_string();
                let status = parse_ver(&v).map(classify).unwrap_or("UNKNOWN_VERSION").to_string();
                return Record { domain, wp_detected: true, version: Some(v), source: "feed", status };
            }
        }

        // 4) /wp-json/ — confirms WordPress even when version is hidden.
        if !wp_detected {
            if let Some(body) = fetch(&client, &format!("{base}/wp-json/")).await {
                reachable = true;
                if body.contains("\"namespace\"") || body.contains("wp/v2") {
                    wp_detected = true;
                }
            }
        }

        if reachable {
            break; // got a working scheme, don't retry the other one
        }
    }

    let status = if !reachable {
        "UNREACHABLE"
    } else if wp_detected {
        "UNKNOWN_VERSION" // WP confirmed but version hidden — can't judge safely
    } else {
        "NOT_WORDPRESS"
    };

    Record { domain, wp_detected, version: None, source: "-", status: status.to_string() }
}

#[tokio::main]
async fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| "domains.txt".to_string());
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Could not read '{path}': {e}");
            std::process::exit(1);
        }
    };

    let domains: Vec<String> = text
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_string())
        .collect();

    let client = reqwest::Client::builder()
        .user_agent(UA)
        .timeout(Duration::from_secs(TIMEOUT_SECS))
        .danger_accept_invalid_certs(true) // recon: don't skip hosts with bad certs
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .expect("client build");

    println!("domain,wp_detected,version,source,status");

    let results: Vec<Record> = stream::iter(domains.into_iter().map(|d| {
        let client = client.clone();
        async move { check(client, d).await }
    }))
    .buffer_unordered(CONCURRENCY)
    .collect()
    .await;

    let mut vuln = 0usize;
    for r in &results {
        println!(
            "{},{},{},{},{}",
            r.domain,
            r.wp_detected,
            r.version.as_deref().unwrap_or("-"),
            r.source,
            r.status
        );
        if r.status == "VULNERABLE" {
            vuln += 1;
        }
    }

    eprintln!(
        "\nDone: {} hosts, {} VULNERABLE. Review VERIFY_BACKPORT and UNKNOWN_VERSION manually.",
        results.len(),
        vuln
    );
}
