# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## v0.3.0 (2021-09-01)

* BREAKING: minimum ueberauth version is now 0.7
* Standardize handling of CSRF Attack protection

## v0.2.0 (2020-05-28)

* BREAKING: minimum Elixir version is now 1.7
* Added per app configuration based on the otp_app
* Support some optional parameters for Cognito `/authorize`
* Modified to return `info/1` with the information of User in `Ueberauth.Auth.Info`

Thank you to @mdillavou and @yagince for their contributions to this release!

## v0.1.0 (2019-12-19)

* Initial release
