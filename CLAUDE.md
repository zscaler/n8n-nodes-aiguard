# n8n-nodes-aiguard

n8n community node package for Zscaler AI Guard (AI Runtime Security). Scans AI prompts and responses for security threats — toxicity, PII, secrets, prompt injection — within n8n workflows.

## Project Structure

```sh
n8n-nodes-aiguard/
├── nodes/AIGuard/
│   ├── AiGuard.node.ts     # Node implementation (operations, scanning logic, retries)
│   └── aiguard.svg          # Node icon (copied to dist/ at build time)
├── credentials/
│   └── AIGuardApi.credentials.ts  # Credential type (API key, cloud, policy ID, auth config)
├── dist/                    # Compiled output (not committed)
├── eslint.config.js         # Source linter (n8n-nodes-base rules + TypeScript)
├── eslint.community.config.mjs  # Dist linter (mirrors n8n Creator Portal scanner)
├── .releaserc.json          # semantic-release config (conventional commits → npm + GitHub)
└── .github/workflows/
    ├── release.yml           # CI: verify → semantic-release (tag, npm publish, GitHub Release)
    └── weekly-ci.yml         # Weekly smoke: audit, build, lint, test (Node 22.x + 24.x)
```

## Architecture

The package has two components:

1. **Credential (`AIGuardApi`)** — Stores API key, cloud region, optional override URL, and optional policy ID. Defines `authenticate` config with Bearer token headers. Includes a credential test that sends a real scan request.

2. **Node (`AiGuard`)** — Three operations: Prompt Scan (direction IN), Response Scan (direction OUT), Dual Scan (both). Uses `AIGuardScanner` class which calls `httpRequestWithAuthentication('aiGuardApi', ...)` to leverage the credential's auth config. Retries via `executeScanWithRetries()`.

### Request Flow

```sh
n8n workflow item
    → AiGuard.execute() reads credentials, builds base URL
    → AIGuardScanner.executeScan() calls httpRequestWithAuthentication
    → AI Guard API (https://api.{cloud}.zseclipse.net/v1/detection/...)
    → Response enriched with workflow metadata → output
```

### API Endpoints

- Policy ID provided → `POST /v1/detection/execute-policy`
- No Policy ID → `POST /v1/detection/resolve-and-execute-policy`

## Development

### Prerequisites

- Node.js >= 22.0.0
- npm >= 10.0.0

### Setup

```bash
npm install
npm run build
```

### Commands

```bash
npm run build         # TypeScript compile + copy SVG icons to dist/
npm run dev           # TypeScript watch mode
npm run lint          # ESLint on source (n8n-nodes-base rules)
npm run lint:dist     # ESLint on dist/ (n8n Creator Portal rules)
npm run scan:local    # build + lint:dist (pre-publish check)
npm run format        # Prettier on nodes/ and credentials/
npm run lintfix       # Auto-fix lint issues
npm test              # Jest
npm run test:coverage # Jest with coverage
```

### Validation Before Publishing

Two-step validation mirrors the n8n Creator Portal:

1. **Before publish**: `npm run scan:local` — builds dist/ and runs the same ESLint rules the Creator Portal uses
2. **After publish**: `npm run scan:npm` — downloads the published tarball from npm and scans it (only works after `npm publish`)

### Local Testing with n8n

```bash
npm run build

# Native n8n
ln -s $(pwd) ~/.n8n/custom/n8n-nodes-aiguard

# Docker n8n
# -v /path/to/n8n-nodes-aiguard:/home/node/.n8n/custom/n8n-nodes-aiguard
```

Restart n8n after linking.

## Critical Conventions

### n8n Node Requirements

These rules come from the n8n manual review process and must be followed:

- **Authentication**: Always use `httpRequestWithAuthentication('aiGuardApi', ...)` instead of `httpRequest()` with manual auth headers. The credential's `authenticate` config handles Bearer token injection.
- **Error types**: Use `NodeApiError` for HTTP/API errors (preserves status code and response body in the UI). Use `ApplicationError` for validation errors. Use `NodeOperationError` for node configuration errors. Never use plain `Error` inside the execute block.
- **Connection types**: Use `NodeConnectionTypes.Main` from `n8n-workflow` for `inputs`/`outputs` (not string literals). The source eslint rule that conflicts with this is disabled in `eslint.config.js`.
- **Credential icon**: The credential class must have `icon = 'file:aiguard.svg' as const`. The build script copies the SVG to both `dist/nodes/AIGuard/` and `dist/credentials/`.
- **Operation ordering**: Operation options in the `description.properties` must be sorted alphabetically by display name.
- **`this` binding**: When calling `httpRequestWithAuthentication` from a helper class outside the node, use `.call(this.context, ...)` to bind the correct execution context.

### Error Handling

The node is fail-closed by design:

- When `continueOnFail()` is true, errors produce `{ action: "BLOCK", blocked: true }` — never silently allows content
- Content over 5 MB is rejected before the API call (`ApplicationError`)
- Timeouts and HTTP errors throw `NodeApiError` with status code context
- Retries are capped at max 6 attempts

### Security

- API keys are stored encrypted via n8n's credential system
- No content is logged or persisted by the node
- All communication uses HTTPS/TLS
- Error messages do not leak sensitive data (response bodies truncated to 300 chars)

## Two ESLint Configurations

The project has two separate ESLint configs with different purposes:

1. **`eslint.config.js`** (source) — Runs on TypeScript in `nodes/` and `credentials/`. Uses `plugin:n8n-nodes-base/nodes`. Two rules disabled because the n8n manual review requires `NodeConnectionTypes.Main` which conflicts with the plugin's string literal expectation.

2. **`eslint.community.config.mjs`** (dist) — Runs on compiled JS in `dist/`. Uses `@n8n/eslint-plugin-community-nodes` recommended config. This matches exactly what the n8n Creator Portal scanner checks. Must pass clean for npm publication.

Both must pass before publishing (`prepublishOnly` runs build + lint + lint:dist).

## Releasing

Automated via [semantic-release](https://github.com/semantic-release/semantic-release) on push to `main`/`master`.

- Version is derived from Conventional Commits (`fix:` → patch, `feat:` → minor, `BREAKING CHANGE:` → major)
- semantic-release updates `package.json`, creates git tag `vX.Y.Z`, publishes to npm with provenance, and creates a GitHub Release
- Prerelease channels: `beta` and `alpha` branches publish e.g. `1.0.0-beta.1`

### 0.x Version Guard

semantic-release's first automated release is always `1.0.0` if no `vX.Y.Z` tags exist (it ignores `package.json`). The Release workflow has a guard step that fails if `package.json` is `0.x` but no semver git tags are present. Tag every published version before the first release run:

```bash
git tag v0.1.0 <commit-sha>
git tag v0.1.2 <commit-sha>
git push origin --tags
```

### Required Secrets

- `NPM_TOKEN` — npm automation token with publish rights for `@bdzscaler`

## CI Pipelines

### Release Workflow (`.github/workflows/release.yml`)

Triggered on push to `main`/`master`/`beta`/`alpha` and PRs to `main`/`master`.

Steps: `npm audit --omit=dev` → build → Prettier check → lint → lint:dist → Jest → semantic-release (push only)

### Weekly CI (`.github/workflows/weekly-ci.yml`)

Runs Monday 06:00 PST, on push/PR to main, and manual dispatch. Tests on Node 22.x and 24.x.

Steps: `npm audit --omit=dev` → build → Prettier check → lint → lint:dist → Jest

## Adding a New Operation

1. Add the option to the `operation` property in `AiGuard.description.properties` — **maintain alphabetical order**
2. Add a `case` in the `switch (operation)` block in `execute()`
3. Build the scan payload using `buildPayload()` with the appropriate direction
4. Call `executeScanWithRetries()` and assign to `scanResult`
5. Run `npm run build && npm run lint && npm run lint:dist` to verify

## Adding a New Credential Field

1. Add the property to `AIGuardApi.credentials.ts` in the `properties` array
2. Update the `AIGuardCredentials` interface in `AiGuard.node.ts`
3. Update the credential test in `AIGuardApi.credentials.ts` if needed
4. Run `npm run build && npm run lint && npm run lint:dist` to verify
