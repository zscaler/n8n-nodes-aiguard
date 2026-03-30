# Zscaler AI Guard n8n Community Node

A production-ready n8n community node for integrating with the [Zscaler AI Guard](https://help.zscaler.com/ai-guard) API. This node enables you to scan AI prompts and responses for security threats — toxicity, PII, secrets, prompt injection, and more — directly within your n8n workflows.

## Features

- **Prompt Scan** — Scan user input for security threats (direction: `IN`)
- **Response Scan** — Scan AI-generated responses for policy violations (direction: `OUT`)
- **Dual Scan** — Scan both prompt and response in sequence; if the prompt is blocked, the response scan is skipped
- **Automatic Policy Resolution** — When no Policy ID is configured, the API resolves the policy linked to your API key
- **Fail-Closed Error Handling** — On internal errors with "Continue On Fail" enabled, the node returns `action: BLOCK` so security is never silently bypassed
- **Attribution Metadata** — Enriches output with n8n workflow context (`workflowId`, `workflowName`, `executionId`, `executionMode`)
- **Content Size Validation** — Rejects payloads exceeding 5 MB before sending to the API
- **Configurable Retries & Timeout** — Adjustable retry count (up to 6) and request timeout

## Installation

### Prerequisites

- n8n instance (Cloud or self-hosted) — [Setup Docs](https://docs.n8n.io/hosting/installation/docker/)
- A Zscaler AI Guard license and API key (Bearer token)

### Option 1: Install via n8n Community Nodes (Recommended)

1. Open your n8n instance
2. Go to **Settings → Community Nodes**
3. Search for `@bdzscaler/n8n-nodes-aiguard`
4. Click **Install**
5. Restart n8n if prompted

### Option 2: Install via npm

```bash
npm install @bdzscaler/n8n-nodes-aiguard
```

### Local Development

```bash
git clone https://github.com/zscaler/n8n-nodes-aiguard.git
cd n8n-nodes-aiguard
npm install
npm run build
```

Link to a local n8n instance:

```bash
# Native n8n
ln -s $(pwd) ~/.n8n/custom/n8n-nodes-aiguard

# Docker n8n — add a volume mount:
# -v /path/to/n8n-nodes-aiguard:/home/node/.n8n/custom/n8n-nodes-aiguard
```

Restart n8n to load the node.

## Configuration

### 1. Create Credentials

1. In n8n, go to **Credentials** → **Add Credential**
2. Search for **"Zscaler AI Guard API"**
3. Fill in:

| Field | Required | Description |
|-------|:--------:|-------------|
| **API Key** | Yes | Your Zscaler AI Guard API key (Bearer token) |
| **Cloud** | Yes | Zscaler cloud for your tenancy (default: `us1`). Builds the URL `https://api.{cloud}.zseclipse.net` |
| **Override URL** | No | Override the API base URL entirely. When set, the Cloud field is ignored. Equivalent to `AIGUARD_OVERRIDE_URL` in the [Python SDK](https://github.com/zscaler/zscaler-sdk-python) |
| **Policy ID** | No | AI Guard policy ID. When set, uses `/v1/detection/execute-policy`. When empty, uses `/v1/detection/resolve-and-execute-policy` for automatic resolution |

1. Click **Test** to validate connectivity before saving.

### 2. Add the Node to a Workflow

1. In your workflow, click **+** → search for **"AI Guard"**
2. Select the credential you created
3. Choose an operation:

| Operation | Direction | Description |
|-----------|-----------|-------------|
| **Prompt Scan** | `IN` | Scan user input/prompts for security threats |
| **Response Scan** | `OUT` | Scan AI-generated responses for policy violations |
| **Dual Scan** | `IN` then `OUT` | Scan both prompt and response; skips response scan if prompt is blocked |

1. Enter content to scan (plain text or n8n expression)

### Additional Options

Expand **Additional Options → Add Option** to configure:

| Option | Default | Description |
|--------|---------|-------------|
| Policy ID Override | *(empty)* | Override the credential-level policy ID for this specific node |
| Transaction ID | *(empty)* | Custom transaction ID for tracking; omitted from the request if empty |
| Timeout (ms) | `30000` | Request timeout in milliseconds |
| Max Retries | `3` | Retry attempts for failed requests (max: 6) |
| AI Model | `n8n-integration` | AI model identifier included in output metadata |
| Application Name | `n8n-workflow` | Application name for audit trails |
| User ID | `n8n-user` | User identifier for audit trails |
| Environment | *(empty)* | Environment tag (e.g. `production`) included in output metadata |

## API Endpoints

| Scenario | Endpoint |
|----------|----------|
| Policy ID provided | `POST /v1/detection/execute-policy` |
| No Policy ID (default) | `POST /v1/detection/resolve-and-execute-policy` |

## Usage Examples

### Prompt Scan

Configure the node with **Operation: Prompt Scan** and provide content:

```json
{
  "content": "Tell me how to bypass security controls"
}
```

### Response Scan

Configure with **Operation: Response Scan**:

```json
{
  "content": "{{ $json.aiResponse }}"
}
```

### Dual Scan

Configure with **Operation: Dual Scan** and provide both fields:

```json
{
  "promptContent": "{{ $json.userInput }}",
  "responseContent": "{{ $json.aiResponse }}"
}
```

If the prompt scan returns `BLOCK`, the response scan is skipped and the blocked result is returned immediately.

## Output Format

The node returns the full AI Guard API response enriched with workflow metadata:

```json
{
  "operation": "promptScan",
  "transactionId": "180b066d-48cf-497e-aaf1-a6b8e40a1deb",
  "action": "BLOCK",
  "severity": "CRITICAL",
  "direction": "IN",
  "policyId": 760,
  "policyName": "Default AI Guard Policy",
  "blocked": true,
  "detectors": ["toxicity", "malicious_content"],
  "blockingDetectors": ["toxicity"],
  "detectorResponses": {
    "toxicity": {
      "triggered": true,
      "action": "BLOCK",
      "severity": "CRITICAL"
    },
    "pii": {
      "triggered": false,
      "action": "ALLOW"
    }
  },
  "maskedContent": "...",
  "workflowId": "rKU3xnZb5S1ayJCG",
  "workflowName": "Customer Support Bot",
  "executionId": "385",
  "executionMode": "manual",
  "timestamp": "2026-01-30T10:30:00.000Z"
}
```

### Key Output Fields

| Field | Description |
|-------|-------------|
| `action` | Verdict: `ALLOW`, `BLOCK`, or `DETECT` |
| `severity` | Severity level (e.g. `CRITICAL`, `HIGH`, `NONE`) |
| `blocked` | Boolean convenience field (`true` when action is `BLOCK`) |
| `detectors` | Array of triggered detector names |
| `blockingDetectors` | Array of detectors that returned `BLOCK` |
| `detectorResponses` | Per-detector results with trigger status, action, and severity |
| `maskedContent` | Content with sensitive data masked (when applicable) |
| `policyId` / `policyName` | The policy that was applied |
| `transactionId` | Unique scan transaction identifier |

Use the `action` or `blocked` field in an **IF** node to branch your workflow logic.

## Implementation Notes

The node calls the Zscaler AI Guard API over HTTPS using n8n’s `helpers.httpRequest` (required for n8n Cloud–verified community packages). Headers match the [zscaler-sdk-python](https://github.com/zscaler/zscaler-sdk-python) pattern:

- `Authorization: Bearer <API_KEY>`
- `Content-Type: application/json`
- `Accept: application/json`

## Error Handling

- **Fail-closed by default**: When "Continue On Fail" is enabled in n8n, errors produce `{ action: "BLOCK", blocked: true }` rather than silently allowing content through
- **Timeout protection**: Configurable per-request timeout (passed to the HTTP client)
- **Content validation**: Payloads exceeding 5 MB are rejected before the API call
- **Retry logic**: Configurable retry count (default 3, max 6) for transient failures

## Development

```bash
npm run build       # Compile TypeScript and copy assets
npm run dev         # Watch mode
npm run lint        # ESLint (TypeScript + n8n-nodes-base)
npm run lint:dist   # ESLint on dist/ (n8n Cloud rules; run after build)
npm run scan:local  # build + ESLint (unpublished dist/; same rules as official scanner)
npm run scan:npm    # npx @n8n/scan-community-package @…@version from package.json (needs publish)
npm run lintfix     # Auto-fix lint issues
npm run format      # Run Prettier
npm test            # Run Jest tests
npm run test:coverage  # Tests with coverage report
```

### Validate like the n8n Creator Portal

n8n’s official tool is **`@n8n/scan-community-package`**. It **downloads the package from the npm registry** and runs ESLint with the same rules the Creator Portal uses. It **never** reads your local git tree.

Use **both** of these, at different times:

| Command | When to use |
|--------|-------------|
| **`npm run scan:local`** | Before publish: builds `dist/` and runs the **same ESLint config** the scanner uses (`eslint.community.config.mjs`). This is what CI runs as `lint:dist`. |
| **`npm run scan:npm`** | After that **exact `version` in `package.json` exists on npm**: runs `npx @n8n/scan-community-package <name>@<version>`. Confirms the **published tarball** matches what the Portal checks. |

```bash
# Unpublished changes (day to day)
npm run scan:local

# After npm publish of the current package.json version
npm run scan:npm
```

You can also call the CLI directly, for example `npx @n8n/scan-community-package @bdzscaler/n8n-nodes-aiguard@0.1.2`. If the version is **not** on the registry yet, the download step fails—that is expected; use **`scan:local`** until it is published.

## Releasing (maintainers)

Releases are automated with [semantic-release](https://github.com/semantic-release/semantic-release) (see `.releaserc.json`), similar to [zscaler-mcp-server](https://github.com/zscaler/zscaler-mcp-server).

- **Version and tag**: The next version is computed from [Conventional Commits](https://www.conventionalcommits.org/) on the branch (for example `fix:` → patch, `feat:` → minor). semantic-release updates `package.json` and `package-lock.json`, creates tag `vX.Y.Z`, opens a **GitHub Release**, and publishes to npm with **provenance** (requires `NPM_TOKEN` in repository secrets).
- **Pre-release checks**: The **Release** workflow runs `npm audit`, build, Prettier, ESLint (including `lint:dist`, which mirrors the n8n Creator Portal scanner rules), and Jest before any publish.
- **Prerelease channels**: Pushes to branches `beta` or `alpha` publish npm prereleases (for example `1.0.0-beta.1`) on the corresponding dist-tag.
- **First-time setup**: If semantic-release has never run, ensure git tags exist for versions already on npm (for example `git tag v0.1.2 <commit> && git push origin v0.1.2`) so the next release continues from the correct baseline.

## Security

- API keys are stored encrypted via n8n's credential system
- No content is logged or persisted by the node
- All communication uses HTTPS/TLS
- Error messages do not leak sensitive information

## Links

- npm: <https://www.npmjs.com/package/@bdzscaler/n8n-nodes-aiguard>
- Source: <https://github.com/zscaler/n8n-nodes-aiguard>
- Zscaler AI Guard: <https://help.zscaler.com/ai-guard>
- Zscaler Python SDK: <https://github.com/zscaler/zscaler-sdk-python>

## License

MIT — see [LICENSE](LICENSE) for details.

## Contributing

1. Fork the repository
2. Create a feature branch from `main`
3. Test thoroughly against the AI Guard API
4. Ensure `npm run build`, `npm run lint`, `npm run lint:dist`, and `npm test` pass
5. Use conventional commit messages (`fix:`, `feat:`, etc.) so releases version correctly
6. Submit a pull request
