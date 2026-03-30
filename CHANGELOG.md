# Changelog

All notable changes to **@bdzscaler/n8n-nodes-aiguard** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] — 2026-03-30

### Changed

- Package `author.email` set to **devrel@zscaler.com** (npm / Creator Portal verification contact).

## [0.1.0] — 2026-03-30

### Added

- Initial release of the **Zscaler AI Guard** n8n community node (`aiGuard`).
- **Operations:** Prompt Scan, Response Scan, and Dual Scan (prompt then response, with early exit if the prompt is blocked).
- **Credentials:** Zscaler AI Guard API (API key, cloud, optional override URL, optional policy ID for `execute-policy` vs automatic `resolve-and-execute-policy`).
- **Outputs:** Policy results including action, severity, detectors, blocking detectors, and workflow context where available.
- **Limits:** Request timeout, configurable retries, and a 5MB content-size guard.
- **Packaging:** MIT-licensed community node with `n8n-community-node-package` metadata for installation from npm.

[0.1.1]: https://github.com/zscaler/n8n-nodes-aiguard
[0.1.0]: https://github.com/zscaler/n8n-nodes-aiguard
