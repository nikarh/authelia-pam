//! Checks a username and password with Authelia (`/api/firstfactor`), then that the user may access a protected URL
//! (`/api/authz/auth-request`): exit status 0 when both pass, 1 otherwise. For `pam_exec` and for Home Assistant's
//! `command_line` authentication provider (`--meta` prints the user's display name).

use std::env;
use std::io::{self, Read};
use std::process;
use std::time::Duration;

use ureq::Agent;
use ureq::tls::{RootCerts, TlsConfig};

type Error = Box<dyn std::error::Error>;

/// Longer than any real username or password: refused before anything is sent.
const MAX_USERNAME: usize = 256;
const MAX_PASSWORD: usize = 4096;
/// The most of an answer that is read: Authelia's are a few hundred bytes.
const MAX_RESPONSE: u64 = 256 * 1024;
const TIMEOUT: Duration = Duration::from_secs(10);

fn main() {
    match run() {
        Ok(Some(name)) => println!("name = {name}"),
        Ok(None) => {}
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(1);
        }
    }
}

/// Reads a credential from `stdin` or from the environment variable `$NAME`.
fn read_value(source: &str, limit: usize) -> Result<String, Error> {
    let value = if source == "stdin" {
        let mut bytes = Vec::new();
        io::stdin().take(limit as u64 + 1).read_to_end(&mut bytes)?;
        // pam_exec's expose_authtok ends the password with a NUL.
        if bytes.last() == Some(&0) {
            bytes.pop();
        }
        String::from_utf8(bytes).map_err(|_| "the input isn't UTF-8")?
    } else if let Some(name) = source.strip_prefix('$') {
        env::var(name)
            .map_err(|_| format!("environment variable {source} not set (or not UTF-8)"))?
    } else {
        return Err(format!("unsupported source: {source}").into());
    };
    if value.len() > limit {
        return Err(format!("longer than {limit} bytes").into());
    }
    Ok(value)
}

/// A header value this tool sends: nothing that could end the header or start another one.
fn header_safe(v: &str) -> bool {
    !v.is_empty() && v.bytes().all(|b| b == b'\t' || (0x20..0x7f).contains(&b))
}

/// A name for Home Assistant's `name = ...` line: no control characters (a newline would start another line, e.g.
/// `group = system-admin`), trimmed.
fn display_name(name: &str) -> String {
    name.chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .to_owned()
}

/// The cookies Authelia set, as a `Cookie` header: each `name=value`, nothing else.
fn cookies<'a>(set_cookie: impl Iterator<Item = &'a str>) -> Option<String> {
    let pairs: Vec<&str> = set_cookie
        .filter_map(|c| c.split(';').next())
        .map(str::trim)
        .filter(|p| p.contains('=') && header_safe(p))
        .collect();
    (!pairs.is_empty()).then(|| pairs.join("; "))
}

fn agent() -> Agent {
    // The system's certificate authorities: OpenSSL's own with native-tls, the platform verifier with rustls.
    let tls = TlsConfig::builder().root_certs(RootCerts::PlatformVerifier);
    #[cfg(feature = "rustls")]
    let tls = tls.unversioned_rustls_crypto_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ));
    #[cfg(feature = "openssl")]
    let tls = tls.provider(ureq::tls::TlsProvider::NativeTls);
    let tls = tls.build();
    Agent::config_builder()
        .tls_config(tls)
        .timeout_global(Some(TIMEOUT))
        // Non-2xx answers are answers here, not errors.
        .http_status_as_error(false)
        .max_redirects(0)
        .build()
        .into()
}

fn run() -> Result<Option<String>, Error> {
    let mut args = pico_args::Arguments::from_env();
    // URL to Authelia
    let authelia_url: String = args.value_from_str("--authelia-url")?;
    // A URL protected by Authelia whose access control rules decide who may log in
    let forwarded_host: String = args.value_from_str("--forwarded-host")?;
    // Print `name = <display name>` for Home Assistant
    let meta = args.contains("--meta");
    let username_source: Option<String> = args.opt_value_from_str("--username-src")?;
    let password_source: Option<String> = args.opt_value_from_str("--password-src")?;
    let rest = args.finish();
    if !rest.is_empty() {
        return Err(format!("unexpected arguments: {rest:?}").into());
    }
    let authelia_url = authelia_url.trim_end_matches('/');
    if !(authelia_url.starts_with("https://") || authelia_url.starts_with("http://"))
        || !header_safe(authelia_url)
    {
        return Err("--authelia-url must be an http(s) URL".into());
    }
    if !header_safe(&forwarded_host) || !forwarded_host.contains("://") {
        return Err("--forwarded-host must be a URL".into());
    }

    let username = read_value(
        username_source.as_deref().unwrap_or("$PAM_USER"),
        MAX_USERNAME,
    )
    .map_err(|e| format!("username: {e}"))?;
    let password = read_value(password_source.as_deref().unwrap_or("stdin"), MAX_PASSWORD)
        .map_err(|e| format!("password: {e}"))?;
    if username.is_empty() || password.is_empty() {
        return Err("empty username or password".into());
    }

    let agent = agent();
    // First factor: the password. What the user typed goes only into this JSON body, escaped by serde_json.
    let body = serde_json::json!({
        "username": username,
        "password": password,
        "targetURL": forwarded_host,
        "requestMethod": "GET",
        "keepMeLoggedIn": true
    });
    let mut res = agent
        .post(&format!("{authelia_url}/api/firstfactor"))
        .header("Content-Type", "application/json")
        .send(serde_json::to_string(&body)?)
        .map_err(|e| format!("first factor: {e}"))?;
    let status = res.status();
    let text = res
        .body_mut()
        .with_config()
        .limit(MAX_RESPONSE)
        .read_to_string()
        .map_err(|e| format!("first factor: {e}"))?;
    let ok = serde_json::from_str::<serde_json::Value>(&text)
        .ok()
        .and_then(|v| v.get("status").and_then(|s| s.as_str()).map(|s| s == "OK"));
    if status != 200 || ok != Some(true) {
        return Err(format!("first factor refused (HTTP {})", status.as_u16()).into());
    }
    let cookie = cookies(
        res.headers()
            .get_all("Set-Cookie")
            .iter()
            .filter_map(|v| v.to_str().ok()),
    )
    .ok_or("no session cookie in the answer")?;

    // Authorization: may this user access the protected URL with one factor?
    let res = agent
        .get(&format!("{authelia_url}/api/authz/auth-request"))
        .header("Cookie", &cookie)
        .header("X-Original-URL", &forwarded_host)
        .header("X-Original-Method", "GET")
        .call()
        .map_err(|e| format!("authorization: {e}"))?;
    if res.status() != 200 {
        return Err(format!(
            "not authorized for {forwarded_host} (HTTP {})",
            res.status().as_u16()
        )
        .into());
    }

    if !meta {
        return Ok(None);
    }
    // Authelia sends the display name as UTF-8 (`to_str` only takes ASCII).
    let header = |name| {
        res.headers()
            .get(name)
            .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
    };
    let name = header("Remote-Name")
        .or_else(|| header("Remote-User"))
        .map(display_name)
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| display_name(&username));
    Ok(Some(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_cannot_add_lines() {
        assert_eq!(
            display_name("Alice\ngroup = system-admin"),
            "Alicegroup = system-admin"
        );
        assert_eq!(display_name("  Ünï Côdé 😀 \r"), "Ünï Côdé 😀");
    }

    #[test]
    fn only_cookie_pairs() {
        let set = [
            "authelia_session=abc; expires=Thu; path=/; HttpOnly; Secure",
            "x=1",
            "broken",
            "y=2\r\nX-Foo: z",
        ];
        assert_eq!(
            cookies(set.into_iter()).as_deref(),
            Some("authelia_session=abc; x=1")
        );
        assert_eq!(cookies([].into_iter()), None);
    }

    #[test]
    fn header_values() {
        assert!(header_safe("https://app.example.com/path?x=1"));
        for bad in ["", "a\r\nX-Foo: bar", "a\nb", "a\0b", "ü"] {
            assert!(!header_safe(bad), "{bad:?}");
        }
    }
}
