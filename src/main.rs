use std::env;
use std::io::{self};
use std::process;

use ureq::{Agent, tls::TlsConfig};

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {e}");
        process::exit(1);
    }
}

fn read_value(source: &str) -> Result<String, Box<dyn std::error::Error>> {
    if source == "stdin" {
        Ok(io::read_to_string(io::stdin())?)
    } else if source.starts_with('$') {
        env::var(&source[1..])
            .map_err(|_| Box::from(format!("Environment variable {source} not set")))
    } else {
        Err(Box::from(format!("Unsupported source: {source}")))
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config = Agent::config_builder()
        .tls_config(
            TlsConfig::builder()
                .provider(ureq::tls::TlsProvider::NativeTls)
                .root_certs(ureq::tls::RootCerts::PlatformVerifier)
                .build(),
        )
        .build();

    let agent: Agent = config.into();

    // Parse command line arguments
    let mut args = pico_args::Arguments::from_env();

    // URL to authelia server
    let authelia_url: String = args.value_from_str("--authelia-url")?;
    // Forwarded host URL registered in Authelia
    let forwarded_host: String = args.value_from_str("--forwarded-host")?;
    // If set, outputs metadata for Home Assistant
    let meta = args.contains("--meta");

    // Allows dynamic username and password sources.
    // By default, it uses $PAM_USER for username and stdin for password.
    let username_source: Option<String> = args.opt_value_from_str("--username-src")?;
    let username_source = username_source.as_deref().unwrap_or("$PAM_USER");
    let password_source: Option<String> = args.opt_value_from_str("--password-src")?;
    let password_source = password_source.as_deref().unwrap_or("stdin");

    let username = read_value(username_source)?;
    let password = read_value(password_source)?;

    let auth_payload = serde_json::json!({
        "username": username,
        "password": password,
        "targetURL": forwarded_host,
        "requestMethod": "GET",
        "keepMeLoggedIn": true
    });

    let mut res = agent
        .post(&format!("{authelia_url}/api/firstfactor"))
        .header("Content-Type", "application/json")
        .send(serde_json::to_string(&auth_payload)?)
        .map_err(|err| format!("First factor failed: {err}"))?;

    // Parse response body and check if authentication was successful
    let body = res
        .body_mut()
        .read_to_string()
        .map_err(|err| format!("Unable to read body for first factor: {err}"))?;
    let body: serde_json::Value = serde_json::from_str(&body)?;

    if body.get("status").and_then(|v| v.as_str()) != Some("OK") {
        return Err("Auth verify failed".into());
    }

    // Extract session cookie
    let cookie = res
        .headers()
        .get("Set-Cookie")
        .ok_or("No Set-Cookie header found in response")?;

    // Second request: verify authorization
    let res = agent
        .get(&format!("{}/api/authz/auth-request", authelia_url))
        .header("Cookie", cookie)
        .header("X-Original-URL", &forwarded_host)
        .header("X-Original-Method", "GET")
        .call()
        .map_err(|err| format!("Auth request failed: {err}"))?;

    let display_name = res
        .headers()
        .get("remote-name")
        .or_else(|| res.headers().get("remote-user"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or(&username);

    if meta {
        // Echo display name for Home Assistant
        println!("name = {display_name}");
    }

    Ok(())
}
