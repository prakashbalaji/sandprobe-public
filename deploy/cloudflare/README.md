# Cloudflare Sandboxes (PRV-10)

This adapter uses the current native Durable Object Container API and Cloudflare's built-in `cloudflare/debian-trixie` image. It creates a dedicated, authenticated Worker and namespace, then one `lite` container. Native exec inherits PATH rather than the full image environment; the probe's only explicit environment addition is `SANDPROBE_TWIN=1`. This is a declared exec-mode configuration, not an LLM-driven workload or a universal Cloudflare isolation claim.

The management token needs account-scoped Workers Scripts Write, Workers Containers Write and Account Settings Read. It stays in the host process. A separate high-entropy bearer capability authenticates the controller; only its SHA-256 is deployed, and neither credential enters the guest. No DNS/zone, R2, KV, custom image, provider-control probes or snapshots are used. Existing workers.dev setup and Standard account settings must be present; the helper never purchases a plan or changes account-wide subdomains.

Install/bundle locally, without provider mutation:

```sh
cd deploy/cloudflare
npm ci --ignore-scripts
WRANGLER_SEND_METRICS=false npm run check
node --test controller.test.mjs
python3 -m unittest discover -p manage_test.py
```

Run preflight with an owner-only key file, explicit account and a private journal directory. Replace paths/selectors with the reviewed values; no credential belongs on a command line.

```sh
python3 deploy/cloudflare/manage.py preflight --key-file /path/to/key --account ACCOUNT_ID
python3 deploy/cloudflare/manage.py up --key-file /path/to/key --account ACCOUNT_ID \
  --state /private/owned/directory/cloudflare-RUN.state \
  --bundle /tmp/sandprobe-cloudflare-bundle/worker.js
```

The helper records exclusive intent before its first upload. Native mutations are single calls, no automatic retries. Created deployment, namespace and container-application identities are journaled. Ambiguous creation remains an explicit unresolved journal and must not be blindly rerun or adopted. Keep the private journal; it contains the one-run controller capability and must never be committed or printed.

Each controller supports exactly one create, pins guest boot identity, and never restarts a stopped box. An absolute persisted 15-minute alarm and two-minute inactivity timeout backstop deletion. A command deadline includes exec startup/acquisition and destroys the entire container on failure. An expired or changed guest stops the run rather than silently using a replacement.

After `make`, choose **one** of the reviewed test paths per fresh controller:

```sh
# Lifecycle smoke: no containment checks or canary traffic.
SANDPROBE_LIVE_CLOUDFLARE=1 SANDPROBE_CLOUDFLARE_SETUP=/private/owned/directory/cloudflare-RUN.state \
  go test ./internal/host -run '^TestLiveCloudflareLifecycle$' -count=1 -v

# Or the graded baseline, with our independently managed canary already healthy.
bin/sandprobe plan cloudflare -cloudflare-setup /private/owned/directory/cloudflare-RUN.state
bin/sandprobe run cloudflare -cloudflare-setup /private/owned/directory/cloudflare-RUN.state \
  -canary /private/owned/directory/canary.state -out /private/results -y
```

The CLI and smoke test destroy the container and verify the controller reports fenced/not running. This is not an independent provider GET 404. **Also remove the controller resources** after either path:

```sh
python3 deploy/cloudflare/manage.py down --key-file /path/to/key --account ACCOUNT_ID \
  --state /private/owned/directory/cloudflare-RUN.state
```

Cleanup compares deployment identity and the nonce/capability-hash/namespace binding before deleting. Application IDs are checked against their namespace. Worker removal owns namespace teardown; a paginated inventory must prove each recorded namespace absent. Worker names are reusable, leaving a disclosed identity-check/delete race. Unknown/replaced resources are never deleted; unresolved state is kept. Recorded cleanup stages allow verification to finish after the Worker has already disappeared.

Scope: one smoke and one graded baseline, stopping on failure or a suspected provider flaw. No provider approval is claimed. Reports require a credential scan; a suspected provider-side issue stops the run and stays out of every report.
