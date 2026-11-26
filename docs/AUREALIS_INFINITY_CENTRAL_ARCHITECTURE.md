# AUREALIS INFINITY — Central Architecture Blueprint

Status: design baseline / not deployed  
Date: 2026-11-26  
Target mode: GPU cluster  
Initial hardware target: NVIDIA DGX family (DGX Spark candidate node)  
Integration strategy: central-first

## 1. Purpose and non-goals

AUREALIS INFINITY is the orchestration and compute control plane for the user's AI portfolio. It coordinates specialist services without flattening their identities, data boundaries, or product-specific policies.

This document is an architecture proposal. It does not assert that a cluster, DGX hardware, credentials, provider accounts, databases, or deployments are currently connected.

Non-goals for the first milestone:
- no autonomous production deployments or GitHub writes by agents;
- no cross-site account or memory merging by default;
- no model-weight training claims without an actual training pipeline and measured hardware;
- no real-money, wallet, payment, or mining actions from the AI orchestrator.

## 2. Repository reconnaissance (limited, read-only)

The following repository documents and source files were inspected on the default branch. This is a targeted initial review, not a complete audit of every repository or every file.

| Repository | Observed evidence | Initial classification |
|---|---|---|
| `Quantum.KI.Ultra.Pro.V2` | README describes canonical consolidation of Quantum KI Ultra Pro V2, IONOS-7, UltraKI.AI and ultra-ki-v2. Flask API, auth, agent bridge and health endpoints. | Candidate central application / control-plane host |
| `Quantum.AI.` | README describes a Flask/OpenAI Responses API service with health endpoint and environment-based keys. | Specialist inference/chat service |
| `Quantum-Shield` | README describes ULTIMA membership/credit API, site-scoped identities, manual BTC review, production safeguards and approval-only publishing. | Security, membership and policy boundary; keep separate |
| `Omega.Aurealis` | README identifies itself as ASTRALIS Ω educational web prototype; local demo credits, no real auth/backend wallet. | Separate product; not an AI control plane |
| `Neuroforge` | README identifies a landing-page concept; module descriptions are not implementation claims. | Product/brand frontend, not an active compute service |
| `Ultra_KI_Merge` | README contains unresolved Git conflict markers (`<<<<<<<`, `=======`, `>>>>>>>`). | Quarantine from integration until repaired and tested |

Source files inspected in `Quantum.KI.Ultra.Pro.V2`: `app.py`, `requirements.txt`, `agent_bridge.py`, `auth_core.py`, `ionos_core/ionos_ai.py`, `ionos_core/__init__.py`.

Important observations:
- The current app registers an agent identity `quantum-ultra` and a fixed persona in `app.py`.
- IONOS-7 has its own prompt and memory functions; these must remain separately addressable.
- `agent_bridge.py` exposes analysis-only endpoints protected by a shared token, but its current adapter reads an OpenAI-compatible key and model directly from environment variables.
- `auth_core.py` uses SQLite and a local default path unless `AUTH_DB_PATH` is configured. Production persistence must be verified separately.
- The current Flask rate-limit dictionaries are process-local; they are not cluster-wide controls.
- The README for Quantum-Shield explicitly warns that its temporary test database is not production-safe and that real BTC top-ups are disabled by default.

## 3. Target logical architecture

```text
                     ULTIMA / Admin policy boundary
                                |
                     AUREALIS INFINITY API
                                |
              +-----------------+------------------+
              |                 |                  |
        Identity & RBAC    Agent Registry     Job Orchestrator
              |                 |                  |
        tenant/site IDs    Persona Profiles    Queue + Scheduler
              |                 |                  |
              +-----------------+------------------+
                                |
                      Policy / Safety Gateway
                                |
                   Model Router + Provider Adapters
                                |
             +------------------+-------------------+
             |                  |                   |
       DGX inference pool   Cloud model APIs    Specialist services
       (local-first route) (approved fallback) (IONOS-7, Quantum AI,
                                                creative, trading etc.)
             |
       GPU worker agents
             |
     Namespaced memory + artifact store + telemetry
```

### Core services

1. **AUREALIS API** — versioned REST interface, request validation, correlation IDs and service discovery.
2. **Agent Registry** — explicit agent IDs, display names, versioned persona profiles, capabilities, allowed tools, data scope and health status.
3. **Persona Runtime** — composes each agent's own system prompt, model settings, memory namespace and tool permissions. Shared infrastructure must never overwrite a specialist's persona.
4. **Orchestrator** — routes tasks by capability, latency, cost, policy and hardware availability. It records task state and supports retries/idempotency.
5. **Policy Gateway** — deny-by-default tool permissions; separate read, propose, write and deploy scopes. Human approval required for production writes, payments, wallet operations and deployments.
6. **Model Router** — provider-neutral adapters for local inference and approved cloud providers. It reports the actual provider/model selected; no silent claims of local execution.
7. **Memory Service** — tenant-, site- and agent-scoped stores. Shared memory is opt-in, provenance-tagged and access-controlled.
8. **GPU Worker Pool** — isolated inference workers with queue-based scheduling, health checks, resource limits and graceful drain.
9. **Observability** — structured logs, traces, queue depth, GPU utilization, VRAM, latency, error rate, provider spend and audit events.

## 4. Cluster and DGX strategy

The selected operating mode is cluster. The selected initial hardware family is DGX.

Recommended progression:
- **Node 0 / control plane:** deploy AUREALIS API, registry, orchestration, policy and observability separately from model workers.
- **Node 1 / DGX inference:** register a DGX-class node as a GPU worker only after hardware inventory, driver/CUDA compatibility, network isolation, storage and model-serving benchmarks are verified.
- **Scale-out:** add further GPU workers behind the same scheduler; do not assume that a single DGX Spark is equivalent to a multi-GPU DGX rack or that it supports arbitrary multi-node fabric.
- **Cloud fallback:** only use explicitly approved providers, with per-task data classification and spend limits.

A DGX Spark can be evaluated as a compact initial inference/development node. Cluster capacity, multi-node interconnect, model fit, throughput and concurrency must be benchmarked on the actual purchased configuration before production sizing.

## 5. Preserve each AI personality

Every connected agent must have an immutable identity key and a versioned profile. Example registry fields:

- `agent_id`, `display_name`, `persona_version`
- `system_prompt_ref` (secret-free source reference)
- `model_policy` and fallback policy
- `capabilities[]` and `tool_allowlist[]`
- `memory_namespace`, `tenant_scope`, `site_scope`
- `data_classification`, `retention_policy`
- `owner_approval_required`, `active`, `health_endpoint`

Migration rules:
- preserve original prompts and memory stores before adapter changes;
- do not replace an agent's system prompt with a generic AUREALIS prompt;
- do not merge memories or user identities implicitly;
- use compatibility adapters first; migrate one agent at a time;
- keep a rollback mapping to the original endpoint, prompt version and data store.

IONOS-7 and Quantum KI Ultra Pro V2 must remain separate agent identities even while they share the same orchestration plane.

## 6. Integration order (central-first, controlled)

1. Establish AUREALIS API and agent registry in the canonical Quantum KI Ultra Pro V2 repository.
2. Add contract tests for registry, persona isolation, authentication, task routing and policy denial.
3. Integrate IONOS-7 as the first specialist through an adapter; verify its prompt and memory behavior against baseline fixtures.
4. Integrate Quantum.AI as a separate provider/service adapter; compare health and response contracts.
5. Integrate remaining repositories only after individual inventory, ownership, runtime and test review.
6. Treat Quantum-Shield/ULTIMA as an external policy and membership boundary; do not copy its secrets, credit ledger or authentication database into AUREALIS.
7. Exclude `Ultra_KI_Merge` from active integration until the merge-conflict markers are resolved in a dedicated branch and the full test suite passes.
8. Keep frontends and product repositories (including ASTRALIS Ω and Neuroforge) separate from the compute control plane unless a concrete API contract requires integration.

## 7. Security and operational invariants

- Secrets only in managed environment variables/secret stores; never commit them.
- Service-to-service authentication uses rotated credentials and TLS.
- Enforce tenant/site/agent authorization on every request.
- Never trust client-supplied model, role, site ID or agent capability without server-side validation.
- Use a shared Redis/database-backed rate limiter for multi-instance deployments.
- Use durable queues and idempotency keys for distributed jobs.
- Store audit events for privileged actions without logging secrets or full sensitive prompts.
- Production deployment, billing, wallet, payment, membership-credit and GitHub mutation actions require explicit owner approval.
- A health endpoint reporting `ready` is not proof that the provider, GPU, database or downstream agent is operational; health checks must test dependencies independently.

## 8. Required validation gates

No implementation is considered complete until all applicable tests pass and the result is independently observed.

### Architecture / contract tests
- agent IDs are unique and registry lookups are deterministic;
- persona prompt/version for each agent is unchanged by another agent's request;
- memory namespaces reject cross-agent and cross-site reads/writes;
- unauthorized service tokens receive 401/403;
- disabled tools and privileged actions are denied by default;
- malformed, oversized and duplicate task requests are handled safely;
- retries are idempotent and task state survives worker restarts.

### Runtime / cluster tests
- provider health and model identity are reported accurately;
- GPU worker registration, scheduling, drain and recovery work;
- load tests measure throughput, latency, VRAM and failure behavior;
- cloud fallback only occurs when policy allows it;
- rate limiting and queue controls work across multiple API instances;
- database backup and restore are exercised.

### Release gates
- unit and integration tests green;
- security/dependency scan reviewed;
- staging smoke tests pass;
- rollback procedure tested;
- owner approves production deployment;
- deployment URL and running version independently verified.

## 9. Current phase status

- [x] User-selected target recorded: cluster / DGX / central-first.
- [x] Initial targeted repository and source review completed.
- [x] Architecture blueprint written on an isolated feature branch.
- [ ] Full repository inventory and code-level audit.
- [ ] Baseline automated test run and defect report.
- [ ] Implement registry and orchestration contracts.
- [ ] Persona/memory isolation tests.
- [ ] DGX hardware and network readiness verification.
- [ ] Staging integration and load tests.
- [ ] Production approval and deployment verification.

**No cluster connection, hardware provisioning, source-code integration, automated test execution or deployment is claimed by this blueprint.**
