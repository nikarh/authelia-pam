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
  --password-srd 'stdin'
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
        "--password-src, "$password",
        "--meta"
      ]
```

## License

Except where noted (below and/or in individual files), all code in this repository is dual-licensed at your option under either:

- MIT License ([LICENSE-MIT](LICENSE-MIT) or [http://opensource.org/licenses/MIT](http://opensource.org/licenses/MIT))
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0))

[pam-exec]: https://linux.die.net/man/8/pam_exec
[Authelia]: https://www.authelia.com/
[Authelia HTTP API]: https://github.com/authelia/authelia/blob/master/api/openapi.yml
[Home Assistant authentication provider]: https://www.home-assistant.io/docs/authentication/providers/#command-line
