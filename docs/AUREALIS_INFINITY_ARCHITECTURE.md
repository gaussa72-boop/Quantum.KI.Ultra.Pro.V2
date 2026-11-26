# AUREALIS INFINITY — Phase 1 Architecture & Repository Audit

**Status:** architecture proposal on an isolated feature branch; not deployed and not connected to compute hardware.  
**Baseline:** `main` at the time this document was prepared.  
**Execution profile selected:** cluster orchestration; NVIDIA DGX as the first compute node; staged repository integration.

## 1. Goals and non-goals

AUREALIS INFINITY is the control plane for a federated AI system. It coordinates existing AI services without flattening them into one generic assistant.

Goals:
- Keep each existing AI identity, system prompt, memory namespace, tools, and safety policy independent and versioned.
- Route work to specialist agents through authenticated, typed task contracts.
- Use the DGX system as the first local inference/compute node, with additional nodes attachable later.
- Support hybrid fallback to explicitly configured cloud providers.
- Require approval for production writes, deployments, payments, publishing, wallet operations, and destructive actions.
- Make every task, model route, tool invocation, approval, test, and deployment auditable.

Non-goals for Phase 1:
- No automatic merging of repositories.
- No automatic rewriting of system prompts or memory.
- No production deployment, live payment, wallet signing, trading, or unrestricted agent tool access.
- No claim that a DGX machine, cluster scheduler, model runtime, or credentials are currently installed or connected.

## 2. Target architecture

```text
Web / Mobile / Existing AI Services
              |
       API Gateway + Auth
              |
       Policy & Consent Gate
              |
       AUREALIS ORCHESTRATOR
       |        |          |
   Agent      Task       Audit /
  Registry   Planner     Events
       |
   Persona-preserving Agent Adapters
       |
   Model Router / Capability Router
       |                         |
 Local Compute Pool          Cloud Providers
 DGX node 01                 OpenAI / other
 (first node)                (opt-in fallback)
       |
 Additional DGX / GPU nodes (later)
       |
 Isolated data & memory services
 Postgres / vector store / object storage
       |
 Metrics, traces, logs, backups, alerts
```

### Control plane

1. **API Gateway:** stable versioned API, authentication, request limits, schema validation and tenant boundaries.
2. **Policy & Consent Gate:** evaluates identity, role, scope, data classification, budget, and whether a human approval is required.
3. **AUREALIS Orchestrator:** decomposes a request into tasks, selects agents by declared capabilities, handles retries/timeouts, and collects results.
4. **Agent Registry:** stores immutable agent IDs, repository/service ownership, adapter version, persona-manifest hash, allowed tools, model preferences, memory namespace, and health state.
5. **Task Queue:** durable queue with idempotency keys, bounded concurrency, deadlines, retry policy, and dead-letter handling.
6. **Audit/Event Store:** append-only records for task creation, routing, approvals, tool calls, test results, errors, and release events.

### Data plane

- **Model Router:** routes by capability, latency, context size, privacy class, cost ceiling, and model availability. It must report the actual provider/model used.
- **Local Compute Pool:** DGX is registered as node 01 only after installation, driver/runtime checks, secure enrollment, and benchmark acceptance. Additional nodes join through the same node protocol.
- **Cloud fallback:** disabled by default for confidential/local-only tasks; enabled only by explicit policy and configured credentials.
- **Memory services:** separate short-term conversation state, durable user memory, project knowledge, and retrieval indexes. No cross-agent memory access unless explicitly granted.
- **Observability:** health, queue depth, GPU utilization, VRAM/unified-memory pressure, token throughput, latency, errors, and per-agent cost.

## 3. Personality-preservation contract

Every agent keeps its own identity. The orchestrator may delegate a task but must not replace the target agent's identity with AUREALIS's voice.

Required versioned manifest fields:

- `agent_id` — stable, immutable ID.
- `display_name` and `identity_version`.
- `persona_source` — source file or service configuration.
- `persona_sha256` — hash of the approved persona text.
- `system_prompt` — preserved verbatim; edits require a separate reviewed change.
- `memory_namespace` and allowed retrieval collections.
- `capabilities`, `tools_allowlist`, and data-access scope.
- `model_preferences` and fallback policy.
- `approval_policy`, `max_budget`, timeout and rate limits.
- `owner_repository`, deployment URL, health endpoint and adapter version.

Compatibility rule: missing or changed persona hashes block rollout until reviewed. AUREALIS may add a task-specific wrapper outside the persona, but cannot silently mutate the original system prompt. Agent output is attributed to the agent that produced it; orchestration summaries are labelled separately.

## 4. Common task contract

Use a versioned JSON envelope for inter-agent work:

- `task_id`, `correlation_id`, `schema_version`
- `requester`, `target_agent_id`, `requested_capability`
- `objective`, `input_refs`, `data_classification`
- `deadline`, `budget_limit`, `idempotency_key`
- `allowed_actions`, `approval_required`
- response: `status`, `result_refs`, `evidence`, `tests`, `warnings`, `provider_model`, `usage`

Agents return recommendations or typed results. They do not gain another service's credentials. Tool execution is performed by narrowly scoped adapters after policy checks, not by passing secrets between agents.

## 5. Repository findings from the initial read-only audit

The following repositories and their default-branch metadata/files were inspected. This is a source review, not a full clone, dependency installation, runtime test, or production audit.

### `gaussa72-boop/Quantum.KI.Ultra.Pro.V2` — proposed canonical host
- README identifies this as the consolidated main project for Quantum KI Ultra Pro V2, IONOS-7, UltraKI.AI and Ultra KI V2.
- Contains `ionos_core`, `auth_core.py`, `agent_bridge.py`, `app.py`, and a Render manifest.
- Existing IONOS modules include separate functions for IONOS, URSPIRIT and MIRROR, but some are explicitly simulated/fallback responses. These identities must be inventoried before any replacement.
- SQLite account/session storage defaults to the repository filesystem; the README correctly warns that Render's ordinary filesystem is not durable.
- Existing `agent_bridge.py` is a useful prototype but is analysis-only and currently uses the OpenAI chat-completions path even though its health check also treats an OpenRouter key as provider-configured. This mismatch needs a tested provider adapter before production use.

### `gaussa72-boop/IONOS-KI`
- Contains an agent catalogue (`agents.json`) with named specialist roles: AUREON, AEGIS, ATLAS, MERCATOR, LEDGER, NEXUS, MNEMOS, ARGUS, HERMES and ORACLE.
- The catalogue explicitly marks several sites as excluded and sets supervised execution, no autonomous deployments, and provider-verification requirements. These constraints should be imported as policy data, not discarded.
- `ai_core.py` currently returns simple random/rule-based responses; `ionos_ai.py` in the canonical project has a separate IONOS-7 identity and memory. These are not interchangeable without parity tests.
- `main.py` mixes a Tkinter entry point with repeated nested infinite loops/imports. It should not be used as a production web entry point.
- Render configuration specifies Python 3.11.11, while other project documentation references different Python versions; runtime versions need reconciliation.

### `gaussa72-boop/Quantum.AI.`
- Has a Flask API, separate Quantum.AI system identity, session handling, health endpoint and a provider configuration.
- Its Render manifest has `autoDeploy: true`; this is a release-policy conflict with the proposed supervised staged rollout and must be reviewed before production integration.
- The same prototype agent bridge is present; the shared adapter should be extracted only after contract and regression tests.

### `gaussa72-boop/Ultra_KI_Merge`
- README contains unresolved Git conflict markers (`<<<<<<<`, `=======`, `>>>>>>>`), so the repository is not in a clean documentation state.
- Render start command points to `backend.app:app`; inspected backend code identifies itself as Quantum Mirror Wonderland and contains in-memory demo user/mirror state. It must not be assumed to be the canonical Ultra-KI runtime.
- CORS is configured with a wildcard default in the inspected backend. This must be narrowed before exposing authenticated data.

### `gaussa72-boop/Quantum-Shield`
- README documents site-scoped memberships/credits, manual payment review, approval-gated publishing and no autonomous production writes.
- It explicitly says crypto top-ups are disabled, the initial test database expires, and the current flow does not independently verify Bitcoin transactions. Preserve these safeguards.
- Render manifest uses a free PostgreSQL database and in-memory rate-limit storage; both are unsuitable as a durable multi-instance production baseline without migration.

### `gaussa72-boop/Omega.Aurealis`
- README describes a static ASTRALIS prototype with browser-local demo credits, no real authentication, backend wallet, payments, or multiplayer persistence.
- Keep it as a separate product/agent domain; do not mistake demo credits for production financial balances.

### `ariandomimate-blip/Ate-Rea-Verm-chtnis-chronik`
- Repository is small and currently contains a README and static directory. Full content/persona inventory remains outstanding.

## 6. Staged integration plan

**Stage 1 — Inventory and baseline (current):**
- Freeze the list of candidate repositories and default branches.
- Capture tree, dependencies, runtime manifests, route inventory, persona sources, memory stores, data classifications, existing tests and current deployment configuration.
- Record commit SHAs and persona hashes before any code changes.
- Do not change production services.

**Stage 2 — Contract and compatibility layer:**
- Add a shared, versioned task schema and a minimal authenticated agent adapter.
- Keep adapters inside each repo initially; do not force a monorepo migration.
- Add explicit health/readiness/capability endpoints and correlation IDs.
- Build provider adapters with truthful configured/available/working states.

**Stage 3 — AUREALIS control plane:**
- Implement registry, policy gate, orchestrator, queue, audit store and approval workflow in a dedicated service/repository.
- Start with read-only planning and analysis tasks.
- Add per-agent memory isolation and provenance-aware retrieval.

**Stage 4 — DGX cluster enrollment:**
- Verify the exact DGX model, OS image, firmware, network, storage, drivers and supported inference runtimes.
- Enroll one DGX node; benchmark representative models and concurrency.
- Add a second node only after networking, scheduling, health and failover tests pass.
- Keep cloud fallback explicit and policy-controlled.

**Stage 5 — Canary integration:**
- Attach one low-risk agent at a time.
- Run identity/persona regression tests, API contract tests, security tests, load tests and failure injection.
- Compare outputs against the pre-integration baseline; block release on unexplained identity drift or data leakage.

**Stage 6 — Controlled rollout:**
- Promote by pull request and reviewed release tag.
- Require human approval for production deployment and irreversible actions.
- Use canary, health gates, rollback criteria, backups and post-deploy smoke tests.

## 7. Required test gates

1. **Persona integrity:** approved persona hashes unchanged; golden prompt tests for each agent; language/style/role regressions; attribution correctness.
2. **Contract:** schema validation, auth failures, replay/idempotency, timeouts, retries, cancellation and malformed payloads.
3. **Isolation:** cross-agent and cross-site memory access denied by default; tenant boundary and token-scope tests.
4. **Security:** secret scanning, dependency audit, CORS allowlist, CSRF/auth checks, rate limits, input-size limits, SSRF controls and audit-log redaction.
5. **Reliability:** provider unavailable, node lost, queue backlog, database outage, duplicate task and worker restart.
6. **Performance:** cold start, throughput, p50/p95 latency, memory pressure, model concurrency and thermal/power constraints.
7. **Release:** clean build, unit/integration tests, health/readiness checks, canary smoke tests and rollback rehearsal.

No test gate is considered passed until its command, environment, result and commit SHA are recorded.

## 8. Current blockers and next evidence needed

- Obtain full recursive file inventories and exact commit SHAs for all candidate repositories.
- Inspect every active agent's actual system prompt, memory backend, route surface and test suite; the current sample is not a complete persona census.
- Resolve the canonical ownership map for overlapping IONOS/Quantum/Ultra projects before selecting any runtime as source of truth.
- Confirm DGX model/SKU, availability, network design, storage, power/cooling, operating system and supported inference stack.
- Confirm where AUREALIS control-plane state will live (managed PostgreSQL, queue, object store, secrets manager and backup policy).
- Reconcile automatic deployment settings with supervised approvals.
- Run builds and tests in a reproducible checkout/CI runner; GitHub file inspection alone cannot prove runtime correctness.

**Release decision:** Phase 1 architecture draft only. No production code was changed, no service was deployed, no DGX node was enrolled, and no runtime tests were executed in this phase.
