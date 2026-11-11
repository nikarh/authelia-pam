//! Runs the binary against a real Authelia in a container (`tests/authelia/`): one rule per kind of access control,
//! users with odd names and passwords, and inputs meant to break or trick the tool. Needs Docker or Podman, so it is
//! ignored by default:
//!
//!     cargo test --features rustls --test authelia -- --ignored
//!
//! `CONTAINER_ENGINE` picks the engine (default: docker, else podman), `AUTHELIA_PAM_TEST_PORT` the host port (9091).

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// The Authelia image, pinned by digest (CI pulls the same).
const IMAGE: &str = include_str!("authelia/image");
const ALICE_PASSWORD: &str = "Ålïce \"pa$$\" \\ ;&|`(id)$HOME %{} ✓😀 'x'";

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/authelia")
}

fn engine() -> String {
    std::env::var("CONTAINER_ENGINE").unwrap_or_else(|_| {
        let has = |e: &str| {
            Command::new(e)
                .arg("--version")
                .output()
                .is_ok_and(|o| o.status.success())
        };
        if has("docker") {
            "docker".into()
        } else {
            "podman".into()
        }
    })
}

/// The container, removed when the test ends however it ends.
struct Authelia {
    engine: String,
    name: String,
    url: String,
}

impl Drop for Authelia {
    fn drop(&mut self) {
        let _ = Command::new(&self.engine)
            .args(["rm", "-f", &self.name])
            .output();
    }
}

fn start() -> Authelia {
    let engine = engine();
    let port = std::env::var("AUTHELIA_PAM_TEST_PORT").unwrap_or_else(|_| "9091".into());
    let name = format!("authelia-pam-test-{}", std::process::id());
    let volume = format!(
        "{}:/config:ro{}",
        dir().display(),
        if engine.ends_with("podman") { ",Z" } else { "" }
    );
    let out = Command::new(&engine)
        .args([
            "run",
            "-d",
            "--rm",
            "--name",
            &name,
            "-p",
            &format!("127.0.0.1:{port}:9091"),
            "-v",
            &volume,
            IMAGE.trim(),
        ])
        .output()
        .expect("running the container engine");
    assert!(
        out.status.success(),
        "starting Authelia: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let authelia = Authelia {
        engine,
        name,
        url: format!("https://auth.example.localhost:{port}"),
    };
    let deadline = Instant::now() + Duration::from_secs(60);
    // Ready once a request gets an answer from Authelia itself (a wrong password).
    while !run(&authelia, "nobody", "x", "one", Input::Env)
        .get()
        .1
        .contains("first factor refused")
    {
        assert!(Instant::now() < deadline, "Authelia didn't start");
        std::thread::sleep(Duration::from_millis(200));
    }
    authelia
}

#[derive(Clone, Copy)]
enum Input {
    /// `--username-src '$username' --password-src '$password'`, as Home Assistant does.
    Env,
    /// The username in `$PAM_USER`, the password on stdin, as pam_exec does (with its trailing NUL).
    Pam,
}

/// A run of the binary in a thread of its own: Authelia delays every failed login on purpose, so the cases run
/// together, not one after another.
struct Pending(std::thread::JoinHandle<(i32, String, String)>);

impl Pending {
    /// (exit code, stderr, stdout)
    fn get(self) -> (i32, String, String) {
        self.0.join().expect("a run panicked")
    }
}

fn run_raw(a: &Authelia, username: &[u8], password: &[u8], host: &str, input: Input) -> Pending {
    let (url, username, password, host) = (
        a.url.clone(),
        username.to_vec(),
        password.to_vec(),
        host.to_owned(),
    );
    Pending(std::thread::spawn(move || {
        exec(&url, &username, &password, &host, input)
    }))
}

fn exec(
    url: &str,
    username: &[u8],
    password: &[u8],
    host: &str,
    input: Input,
) -> (i32, String, String) {
    use std::os::unix::ffi::OsStrExt;
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_authelia-pam"));
    cmd.args([
        "--authelia-url",
        url,
        "--forwarded-host",
        &format!("https://{host}.example.localhost/"),
        "--meta",
    ])
    .env("SSL_CERT_FILE", dir().join("ca.crt"))
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    let mut stdin = Vec::new();
    match input {
        Input::Env => {
            cmd.args(["--username-src", "$username", "--password-src", "$password"])
                .env("username", std::ffi::OsStr::from_bytes(username))
                .env("password", std::ffi::OsStr::from_bytes(password));
        }
        Input::Pam => {
            cmd.env("PAM_USER", std::ffi::OsStr::from_bytes(username));
            stdin.extend_from_slice(password);
            stdin.push(0);
        }
    }
    let started = Instant::now();
    let mut child = cmd.spawn().expect("running authelia-pam");
    let mut pipe = child.stdin.take().expect("stdin");
    let writer = std::thread::spawn(move || {
        let _ = pipe.write_all(&stdin);
    });
    let out = child.wait_with_output().expect("waiting for authelia-pam");
    let _ = writer.join();
    assert!(
        started.elapsed() < Duration::from_secs(15),
        "took {:?}",
        started.elapsed()
    );
    let code = out
        .status
        .code()
        .unwrap_or_else(|| panic!("killed by a signal: {:?}", out.status));
    assert!(code == 0 || code == 1, "exit code {code}");
    (
        code,
        String::from_utf8_lossy(&out.stderr).into_owned(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

fn run(a: &Authelia, username: &str, password: &str, host: &str, input: Input) -> Pending {
    run_raw(a, username.as_bytes(), password.as_bytes(), host, input)
}

#[test]
#[ignore = "needs Docker or Podman: cargo test --features rustls --test authelia -- --ignored"]
fn against_authelia() {
    let a = start();
    let mut failures = Vec::new();
    let mut pending: Vec<(String, Pending, Result<String, ()>)> = Vec::new();
    let mut check = |what: &str, run: Pending, expected: Result<&str, ()>| {
        pending.push((what.to_owned(), run, expected.map(str::to_owned)));
    };
    let bob = "bob-password";
    let ok = |name| Ok::<&str, ()>(name);
    let no = Err::<&str, ()>(());

    // Credentials, for both ways of passing them.
    for input in [Input::Env, Input::Pam] {
        check(
            "alice, her odd password",
            run(&a, "alice", ALICE_PASSWORD, "one", input),
            ok("Ålïce Ünïcode 😀"),
        );
        check("bob", run(&a, "bob", bob, "one", input), ok("Bob Builder"));
        check(
            "a unicode username",
            run(&a, "dävé", "dave-password", "one", input),
            ok("Dävé"),
        );
        check(
            "a wrong password",
            run(&a, "bob", "bob-passwor", "one", input),
            no,
        );
        check("an unknown user", run(&a, "mallory", bob, "one", input), no);
        check(
            "a disabled user",
            run(&a, "carol", "carol-password", "one", input),
            no,
        );
    }

    // Access control: the protected URL's rule decides.
    check(
        "two factors required",
        run(&a, "bob", bob, "two", Input::Env),
        no,
    );
    check("a deny rule", run(&a, "bob", bob, "deny", Input::Env), no);
    check(
        "no rule (default deny)",
        run(&a, "bob", bob, "nothing", Input::Env),
        no,
    );
    check(
        "a bypass rule, right password",
        run(&a, "bob", bob, "bypass", Input::Env),
        ok("Bob Builder"),
    );
    check(
        "a bypass rule doesn't skip the password",
        run(&a, "bob", "wrong", "bypass", Input::Env),
        no,
    );
    check(
        "a group rule, in the group",
        run(&a, "bob", bob, "admins", Input::Env),
        ok("Bob Builder"),
    );
    check(
        "a group rule, not in the group",
        run(&a, "alice", ALICE_PASSWORD, "admins", Input::Env),
        no,
    );
    check(
        "a user rule, that user",
        run(&a, "alice", ALICE_PASSWORD, "alice", Input::Env),
        ok("Ålïce Ünïcode 😀"),
    );
    check(
        "a user rule, another user",
        run(&a, "bob", bob, "alice", Input::Env),
        no,
    );

    // Names that look like another user's.
    for name in [
        "bob ",
        " bob",
        "BOB",
        "Bob",
        "bob\t",
        "bob\n",
        "bob\r\n",
        "b%6fb",
        "bob@example.com",
        "bob\u{200b}",
    ] {
        check(
            &format!("username {name:?}"),
            run(&a, name, bob, "one", Input::Env),
            no,
        );
    }
    // Passwords near another's.
    for password in [
        &format!("{bob} "),
        &format!(" {bob}"),
        &format!("{bob}{bob}"),
        "BOB-PASSWORD",
        "bob-password\n",
        "%",
    ] {
        check(
            &format!("password {password:?}"),
            run(&a, "bob", password, "one", Input::Env),
            no,
        );
    }
    check(
        "alice with bob's password",
        run(&a, "alice", bob, "one", Input::Env),
        no,
    );
    check(
        "bob with alice's password",
        run(&a, "bob", ALICE_PASSWORD, "one", Input::Env),
        no,
    );

    // Inputs meant to break the request or the tool.
    let hostile = [
        "\"}, \"username\": \"bob",
        "bob\", \"password\": \"x",
        "\\\"",
        "\\u0000",
        "\r\nX-Original-URL: https://bypass.example.localhost/\r\n",
        "\r\n\r\nGET / HTTP/1.1",
        "$(touch /tmp/authelia-pam-pwned)",
        "`touch /tmp/authelia-pam-pwned`",
        "; touch /tmp/authelia-pam-pwned",
        "../../../../etc/passwd",
        "%00%0d%0a?#&=/",
        "😀🔥\u{feff}\u{202e}",
        "'; DROP TABLE users; --",
        "{{.Password}}",
        "*",
        "",
    ];
    for s in hostile {
        check(
            &format!("username {s:?}"),
            run(&a, s, bob, "one", Input::Env),
            no,
        );
        check(
            &format!("bob, password {s:?}"),
            run(&a, "bob", s, "one", Input::Env),
            no,
        );
        check(&format!("both {s:?}"), run(&a, s, s, "one", Input::Pam), no);
    }

    // Bytes that environment variables or stdin can carry but aren't text, and NULs inside a password.
    check(
        "a password that isn't UTF-8",
        run_raw(&a, b"bob", b"bob-\xff\xfe", "one", Input::Env),
        no,
    );
    check(
        "a username that isn't UTF-8",
        run_raw(&a, b"b\xc3\x28b", bob.as_bytes(), "one", Input::Env),
        no,
    );
    check(
        "a NUL inside the password",
        run_raw(&a, b"bob", b"bob-pass\0word", "one", Input::Pam),
        no,
    );

    // Very long input: refused before anything is sent, quickly.
    // (An environment variable holds at most 128 kB on Linux: 1 MB goes through stdin.)
    let long = "a".repeat(100 * 1024);
    check(
        "a 100 kB username",
        run(&a, &long, bob, "one", Input::Env),
        no,
    );
    check(
        "a 100 kB password",
        run(&a, "bob", &long, "one", Input::Env),
        no,
    );
    let huge = "a".repeat(1024 * 1024);
    check(
        "a 1 MB password on stdin",
        run(&a, "bob", &huge, "one", Input::Pam),
        no,
    );
    let just_under = "b".repeat(4096);
    check(
        "a 4 kB wrong password",
        run(&a, "bob", &just_under, "one", Input::Pam),
        no,
    );

    // A forwarded host that tries to add a header is refused outright.
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_authelia-pam"));
    let out = cmd
        .args([
            "--authelia-url",
            &a.url,
            "--forwarded-host",
            "https://deny.example.localhost/\r\nX-Original-URL: https://bypass.example.localhost/",
            "--username-src",
            "$username",
            "--password-src",
            "$password",
        ])
        .env("username", "bob")
        .env("password", bob)
        .env("SSL_CERT_FILE", dir().join("ca.crt"))
        .output()
        .expect("running authelia-pam");
    if out.status.code() != Some(1) {
        failures.push(format!(
            "a forwarded host with a header in it: {:?}",
            out.status
        ));
    }

    // The certificate is checked: without the test CA, nothing passes.
    let out = Command::new(env!("CARGO_BIN_EXE_authelia-pam"))
        .args([
            "--authelia-url",
            &a.url,
            "--forwarded-host",
            "https://one.example.localhost/",
        ])
        .args(["--username-src", "$username", "--password-src", "$password"])
        .env("username", "bob")
        .env("password", bob)
        .env("SSL_CERT_FILE", "/dev/null")
        .output()
        .expect("running authelia-pam");
    if out.status.code() != Some(1) {
        failures.push(format!("an untrusted certificate: {:?}", out.status));
    }

    for (what, run, expected) in pending {
        let (code, stderr, stdout) = run.get();
        let ok = match &expected {
            Ok(name) => code == 0 && stdout == format!("name = {name}\n"),
            Err(()) => code == 1 && stdout.is_empty(),
        };
        // Whatever happens, the password isn't echoed.
        let leaked = stderr.contains("pa$$") || stderr.contains("bob-password");
        if !ok || leaked {
            failures.push(format!(
                "{what}: exit {code}, stdout {stdout:?}, stderr {stderr:?}"
            ));
        }
    }
    assert!(
        !std::path::Path::new("/tmp/authelia-pam-pwned").exists(),
        "a shell ran something"
    );
    assert!(
        failures.is_empty(),
        "{} case(s) failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
