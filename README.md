# 🔑 authelia-pam

[![MIT/Apache 2.0](https://img.shields.io/badge/license-MIT%2FApache-blue.svg)](https://github.com/nikarh/authelia-pam#license)
[![GitHub Workflow Status (with event)](https://img.shields.io/github/actions/workflow/status/nikarh/authelia-pam/main.yaml)](https://github.com/nikarh/authelia-pam/actions/workflows/main.yaml)
[![Current Release](https://img.shields.io/github/release/nikarh/authelia-pam.svg)](https://github.com/nikarh/authelia-pam/releases)
[![Release RSS Feed](https://img.shields.io/badge/rss-releases-ffa500?logo=rss)](https://github.com/nikarh/authelia-pam/releases.atom)
[![Main Commits RSS Feed](https://img.shields.io/badge/rss-commits-ffa500?logo=rss)](https://github.com/nikarh/authelia-pam/commits/main.atom)

A [pam-exec] plugin that uses of [Authelia] as an authentication and authorization backend.

## Description

This project is a binary that uses [Authelia HTTP API] to check username, password and permissions.
Note that this project does not support 2FA, since PAM does not provide a sensible way to input 2FA code for the user.

The binary exits with 0 for successful authentication and with 1 for unsuccessful.
In order to run the binary you must provide a number of command line arguments:

```sh
authelia-pam
  # Required, URL to authelia instance
  --authelia-url https://my.authelia \
  # Required, URL domain from access control rule in authelia config
  --forwarded-host https://domain.from.authelia.config.policy \
  # Optional, default value is '$PAM_USER'. Can be either 'stdin' or start with '$' meaning env variable.
  # This is the place from where authelia-pam reads the username.
  # Default is '$PAM_USER', but can be overriden when this program is used for something other than PAM.
  # For example, for [Home Assistant authentication provider] use '$username'.
  --username-src '$PAM_USER' \
  # Optional, default value is 'stdin'. Can be either 'stdin' or start with '$' meaning env variable.
  # This is the place from where authelia-pam reads the password.
  # Default 'stdin', but can be overriden when this program is used for something other than PAM.
  # For example, for [Home Assistant authentication provider] use '$password'. \
  --password-src 'stdin'
  # Optional, if passed would print meta in [Home Assistant authentication provider] format to stdout on successful authentication
  --meta

```

## Using with PAM

An example PAM configuration:

```
auth     required   pam_env.so
auth     required   pam_exec.so expose_authtok quiet /usr/bin/authelia-pam --authelia-url https://my.authelia --forwarded-host https://my.service

account  required   pam_permit.so

session  required   pam_loginuid.so
session  required   pam_limits.so
session  required   pam_permit.so
password required   pam_permit.so
```

## Using with Home Assistant

An example of Home Assistant configuration

```yaml
homeassistant:
  auth_providers:
    - type: command_line
      command: /usr/bin/authelia-pam
      meta: true
      args: [
        "--authelia-url", "https://my.authelia",
        "--forwarded-host", "https://my.service",
        "--username-src", "$username",
        "--password-src", "$password",
        "--meta"
      ]
```

Since this is a username and password provider, Home Assistant logins go through Authelia without 2FA.
If you also want 2FA, or a "Login with Authelia" button that reuses your existing Authelia session, consider [hass-oidc-auth] instead.
It is a Home Assistant integration that adds OpenID Connect login, so authentication, including 2FA, happens on Authelia's own login page, with Authelia configured as an [OpenID Connect provider][Authelia OpenID Connect].

## Builds and TLS

Release archives come in two flavours, both using [ureq] (a small blocking HTTP client, no async runtime):

| Archive | TLS | Runs on | Size, x86_64 (v0.1.7 → now) |
|---|---|---|---|
| `*-linux-gnu-*-openssl` | the system's OpenSSL (native-tls), linked dynamically: needs `libssl.so.3` | glibc distributions | 6.4 MB → 0.7 MB |
| `*-linux-gnu-*-rustls` | rustls with ring, statically linked | glibc distributions without OpenSSL 3 | 1.6 MB → 1.6 MB |
| `*-linux-musl-*-rustls` | rustls with ring, statically linked | anywhere, e.g. Alpine-based containers | 1.7 MB → 1.6 MB (aarch64: 1.43 → 1.36 MB) |

The OpenSSL build used to carry a copy of OpenSSL; it now uses the system's, which is why it is small. A static build
has to carry its TLS: rustls with ring is about 500 kB of it. All builds use `opt-level = "z"` (smaller than `"s"`),
LTO, one codegen unit, `panic = "abort"` and stripped symbols.

The certificate of Authelia is always verified against the system's certificate authorities (OpenSSL's own paths,
or the platform verifier with rustls); `SSL_CERT_FILE` points both at another bundle, e.g. a private CA.

[ureq]: https://github.com/algesten/ureq

## Behaviour and limits

- Exit status 0 only when Authelia accepts the password (`/api/firstfactor`) **and** its access control allows the
  user one-factor access to `--forwarded-host` (`/api/authz/auth-request`); 1 otherwise, with the reason on stderr
  (never the password).
- Usernames longer than 256 bytes and passwords longer than 4096 are refused without asking Authelia; so is input that
  isn't UTF-8. A NUL that `pam_exec` puts after the password is dropped.
- Credentials only ever go into the JSON body, escaped; `--forwarded-host` and cookies are checked for control
  characters before they go into headers. With `--meta`, the display name is printed without control characters, so a
  name can't add lines (such as `group = system-admin`) to Home Assistant's metadata.
- Every connection has a 10 second timeout and answers are read up to 256 kB.

## Tests

`cargo test` runs the unit tests. `tests/authelia.rs` runs the binary against a real Authelia in a container
(`tests/authelia/`: TLS with a test CA, users with unusual names and passwords, one access control rule of each kind):
valid and invalid passwords, unknown and disabled users, one factor, two factors, deny, bypass, group and user rules,
the display name, and inputs meant to break or trick it (look-alike usernames, JSON and header injection attempts,
shell metacharacters, very long and non-UTF-8 input). It needs Docker or Podman and takes a few seconds:

```sh
cargo test --features rustls --test authelia -- --ignored     # or --features openssl
CONTAINER_ENGINE=podman cargo test --features rustls --test authelia -- --ignored
```

## License

Except where noted (below and/or in individual files), all code in this repository is dual-licensed at your option under either:

- MIT License ([LICENSE-MIT](LICENSE-MIT) or [http://opensource.org/licenses/MIT](http://opensource.org/licenses/MIT))
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0))

[pam-exec]: https://linux.die.net/man/8/pam_exec
[Authelia]: https://www.authelia.com/
[Authelia HTTP API]: https://github.com/authelia/authelia/blob/master/api/openapi.yml
[Home Assistant authentication provider]: https://www.home-assistant.io/docs/authentication/providers/#command-line
[hass-oidc-auth]: https://github.com/christiaangoossens/hass-oidc-auth
[Authelia OpenID Connect]: https://www.authelia.com/integration/openid-connect/introduction/
