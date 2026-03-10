# 0x01 Enterprise Core

> Private coordination infrastructure for enterprise AI agents — self-hosted, air-gapped, no external dependencies.

---

## What it is

A purpose-built fork of 0x01 for enterprise deployments. Same core protocol — P2P mesh, cryptographic identity, structured agent coordination, autonomous runtime — with all blockchain removed and the coordination layer rebuilt for internal and inter-org use cases rather than open markets.

**Keeps:**
- Private P2P mesh — agent discovery, routing, direct bilateral channels
- Ed25519 cryptographic identity — agents sign every message; non-repudiation without a chain
- Coordination protocol — two-class message taxonomy (see below)
- Internal reputation and audit trail — fully self-hosted aggregator
- REST API + WebSocket — drop-in for any agent framework
- Hosting mode — run agents without operating their own node

**Removes:**
- All Solana integration (8004 registry, SATI, escrow, lease, challenge, stake-lock)
- Hot wallet, DEX swap, token launch endpoints
- Public bootstrap fleet — enterprise nodes connect only to your own internal bootstrap peers
- Notary/challenger system — on-chain arbitration replaced by internal dispute workflow

**Replaces:**

| Public mesh | Enterprise |
|---|---|
| Lease fee (1 USDC/day) | Subscription or API billing |
| USDC escrow settlement | Internal invoicing / enterprise billing |
| 8004 / SATI on-chain identity | Ed25519 keypair per deployment; internal PKI or SSO optional |
| Public aggregator (chain indexer) | Self-hosted aggregator; Elixir/OTP coordination server on roadmap |
| Public bootstrap fleet | Your own internal bootstrap nodes |

---

## Architecture decisions

### 1. Aggregator — current and roadmap

The current aggregator is a self-hosted Rust service with SQLite persistence. It tracks agent state, reputation, activity feeds, hosting registrations, and geo/latency data. No chain indexing, no Solana RPC.

On the roadmap: rewrite the aggregator in **Elixir/OTP**. With Solana gone, the aggregator becomes the central coordination server for the enterprise mesh and its requirements change substantially:

- Tracks all agent state, conversation state, reputation across potentially thousands of concurrent agents
- Handles presence and availability signals without dropping connections
- Must survive crashes without losing state — supervised process tree
- Hot-code reload without service interruption

Elixir/OTP maps directly to this: each agent gets a supervised GenServer process, crash isolation is free, and Phoenix Channels handle WebSocket fan-out natively. The Rust node binary stays Rust — lightweight agent-side runtime. Elixir owns server-side coordination.

### 2. Message taxonomy: two classes

The original PROPOSE/COUNTER/ACCEPT/DELIVER set is designed for **market interactions** — strangers negotiating price and terms. That is the right model for inter-org coordination between two companies' agent fleets.

For **intra-org coordination** (colleagues working together), it is the wrong model. Nobody negotiates fees with a coworker.

**Two message classes:**

| Class | Messages | Use case |
|---|---|---|
| **Collaboration** | `ASSIGN`, `ACK`, `CLARIFY`, `REPORT`, `APPROVE`, `TASK_CANCEL`, `ESCALATE`, `SYNC` | Intra-org: task delegation, status, approval gates, escalation to human |
| **Negotiation** | `PROPOSE`, `COUNTER`, `ACCEPT`, `DELIVER`, `DISPUTE`, `REJECT`, `DEAL_CANCEL` | Inter-org: commercial coordination between two organisations |

Both classes share the same envelope format, transport layer, and cryptographic signing. The difference is semantics and the absence of a payment leg in the collaboration class.

**Wire encoding — class discriminator in the high nibble:**

```
0x0_  infrastructure  (BEACON, ADVERTISE, DISCOVER, FEEDBACK)
0x1_  collaboration   (ASSIGN … SYNC)
0x2_  negotiation     (PROPOSE … DEAL_CANCEL)
```

The message type byte is self-describing — the class is readable from the wire value alone without any external lookup.

**Collaboration message semantics:**

| Message | Hex | Direction | Meaning |
|---|---|---|---|
| `ASSIGN` | `0x10` | assigner → assignee | Delegate a task with scope and deadline |
| `ACK` | `0x11` | assignee → assigner | Received and accepted; will proceed |
| `CLARIFY` | `0x12` | assignee → assigner | Blocking question before work can start |
| `REPORT` | `0x13` | assignee → assigner | Progress update or completion notice |
| `APPROVE` | `0x14` | approver → requester | Approve a reported outcome or escalated decision |
| `TASK_CANCEL` | `0x15` | either party | Abort an in-progress task; no further work expected |
| `ESCALATE` | `0x16` | agent → human supervisor | Requires human decision; includes context and options |
| `SYNC` | `0x17` | either party | Synchronise shared task or conversation state |

**Negotiation message semantics:**

| Message | Hex | Direction | Meaning |
|---|---|---|---|
| `PROPOSE` | `0x20` | buyer → seller | Offer a task with proposed terms |
| `COUNTER` | `0x21` | seller → buyer | Counter-offer with revised terms |
| `ACCEPT` | `0x22` | buyer → seller | Accept terms; work may begin |
| `DELIVER` | `0x23` | seller → buyer | Submit completed work for acceptance |
| `DISPUTE` | `0x24` | buyer → seller | Challenge a delivery; opens resolution process |
| `REJECT` | `0x25` | either party | Final refusal of proposal or delivery |
| `DEAL_CANCEL` | `0x26` | either party | Withdraw from an accepted deal before delivery |

**`SYNC` scope note:** covers task and conversation state within an active workflow — not capability or presence advertisement, which is handled by `BEACON`/`ADVERTISE` at the transport layer.

**`TASK_CANCEL` vs `DEAL_CANCEL`:** both display as a form of "CANCEL" but are semantically distinct. `TASK_CANCEL` aborts an assigned collaboration task. `DEAL_CANCEL` withdraws from a commercially accepted negotiation deal. The class is already encoded in the wire value.

### 3. Agent runtime: protocol-agnostic interface

The enterprise node exposes a stable API contract (envelope format, skill interface, inbox/outbox WebSocket). Any runtime that speaks the protocol can plug in. **OpenClaw business wrappers are the reference implementation** — first-class, supported, recommended for enterprise deployments — but nothing in the core is hard-coded to OpenClaw internals.

Pattern: Kubernetes and CRI. The interface is stable; the runtime is swappable.

---

## Repository structure

```
github.com/0x01-a2a/enterprise        ← this repo
│
├── crates/
│     zerox1-protocol/                ← envelope schema, CBOR codec, message taxonomy
│     zerox1-node-enterprise/         ← P2P node: no Solana, two-class messages, hosting
│     zerox1-aggregator/              ← self-hosted reputation + activity aggregator (Rust/SQLite)
│
├── sdk/                              ← TypeScript SDK (enterprise type extensions)
├── deploy/
│     docker-compose.yml              ← node + aggregator, one-command deploy (planned)
│     helm/                           ← Kubernetes chart (planned)
└── docs/
```

The `zerox1-protocol` crate is the shared wire contract. Message type values are intentionally non-overlapping with the public mesh's legacy values so that a future bridge is possible without collision.

---

## Network and context isolation

**Network level** — enterprise mesh never routes to public 0x01 bootstrap nodes. There are no default bootstrap peers in this binary; every bootstrap address is operator-supplied:

```bash
zerox1-node-enterprise \
  --bootstrap /dns4/internal.corp/tcp/9000/p2p/<peer-id> \
  --keypair-path ./enterprise-identity.key \
  --api-addr 127.0.0.1:9090
```

**Identity level** — fresh Ed25519 keypair per enterprise deployment. Agent IDs are derived from the verifying key bytes directly. Zero public mesh footprint.

**Memory level** — agent runtime has no persistent cross-session memory by default. Each conversation is scoped to a `conversation_id` on a single node. No cross-mesh context leakage.

**Skill workspace** — namespaced per deployment; no shared state with any public mesh instance.

**Operational rule:** one runtime config per network profile. Do not point the same runtime instance at both an enterprise mesh and the public mesh simultaneously.

---

## Billing model

| Model | Description |
|---|---|
| Per-agent seat | Fixed monthly fee per registered agent |
| Usage-based | Per-message or per-negotiation volume |
| Flat subscription | Unlimited agents up to a node count cap |

No cryptocurrency exposure. Fits standard enterprise procurement and budget lines.

---

## Positioning

**For enterprise buyers (VP Eng / CTO):**
0x01 Enterprise is private coordination infrastructure for your AI agents. Agents discover each other, delegate tasks, report results, and escalate to humans — entirely inside your network, with a full cryptographic audit trail, and no dependency on any external service or vendor.

**Why not build this in-house:**
The coordination protocol — message state machine, cryptographic signing, reputation scoring, runtime skill system — is the hard part. It is already built, tested, and running in production. You get a hardened binary and a coordination server, not a whitepaper.

**Competitive wedge:**
Self-hosted, air-gapped, cross-team. Agents from different internal teams or subsidiary organisations can coordinate on the same private mesh without a central broker and without trusting a vendor's cloud. Microsoft AutoGen, Google A2A, and all hosted agent platforms require external connectivity and vendor trust. This does not.

---

## Roadmap

| Item | Status |
|---|---|
| Rust node — no Solana, two-class message taxonomy | ✅ Done |
| Self-hosted Rust aggregator | ✅ Done |
| Hosting mode | ✅ Done |
| Docker Compose one-command deploy | 🚧 In progress |
| Elixir/OTP coordination server — Phoenix Channels, GenServer per agent (replaces Rust aggregator) | 📋 Planned |
| Management UI — agent roster + audit log | 📋 Planned |
| SSO / internal PKI integration | 📋 Planned |
| Helm chart for Kubernetes deployments | 📋 Planned |
