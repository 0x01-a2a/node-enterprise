# 0x01 Enterprise — Private AI Agent Coordination Infrastructure

> *Your agents. Your network. No vendor, no chain, no exposure.*

---

## The problem

Enterprise AI deployments are hitting a coordination wall.

Teams are running agents — for research, document processing, code review, customer workflows, cross-department automation. But when those agents need to work **together**, the infrastructure isn't there:

- **No standard protocol.** Agents from different teams or vendors can't coordinate without custom glue code per integration.
- **No trust model.** There is no built-in way for an agent to prove who it is, sign its outputs, or hold another agent accountable for a result.
- **No audit trail.** When a multi-agent workflow produces an output, there is no cryptographic record of which agent did what and when.
- **All roads lead to a vendor.** AutoGen, Google A2A, LangGraph Cloud — every platform requires external connectivity, vendor trust, and data leaving your network.

The coordination layer is the missing piece, and nobody wants to build it from scratch.

---

## The solution

**0x01 Enterprise** is a self-hosted, air-gapped coordination layer for AI agents.

Agents discover each other, delegate tasks, report results, escalate to humans, and coordinate commercially across org boundaries — entirely inside your network, with a full cryptographic audit trail.

**No blockchain. No cryptocurrency. No external connectivity required.**

| What you get | How |
|---|---|
| Cryptographic agent identity | Ed25519 keypair per agent; every message is signed |
| Structured coordination protocol | Two message classes: collaboration (intra-org) and negotiation (inter-org) |
| Non-repudiation | Every envelope is signed and logged; full audit trail without a chain |
| Private P2P mesh | libp2p — agents discover and route directly; no central broker |
| Internal reputation | Self-hosted aggregator tracks interaction history and feedback |
| Self-hosted | One binary, one aggregator, Docker Compose deploy; nothing leaves your network |

---

## Two message classes for two coordination modes

Most enterprise deployments have two distinct coordination patterns. We built the protocol around both.

**Collaboration** — agents inside the same org working as a team:

```
Orchestrator  —ASSIGN→    ResearchAgent    "Summarise Q3 filings"
ResearchAgent —ACK→       Orchestrator     "On it"
ResearchAgent —REPORT→    Orchestrator     "Draft ready"
Orchestrator  —ESCALATE→  HumanReviewer   "Needs sign-off"
HumanReviewer —APPROVE→   Orchestrator     "Approved"
Orchestrator  —ASSIGN→    PublishingAgent  "Publish to portal"
```

**Negotiation** — agents from different organisations coordinating commercially:

```
BuyerAgent   —PROPOSE→    VendorAgent   "Translate 200 pages, €500"
VendorAgent  —COUNTER→    BuyerAgent    "€550, 5-day turnaround"
BuyerAgent   —ACCEPT→     VendorAgent
VendorAgent  —DELIVER→    BuyerAgent    (completed translation)
BuyerAgent   —FEEDBACK→   mesh          score: 92
```

Both classes run on the same wire format and transport. The only difference is semantics and the absence of a payment leg in collaboration.

---

## What is built

This is not a whitepaper. The core infrastructure is complete and running.

| Component | Status |
|---|---|
| P2P mesh — libp2p gossipsub, Kademlia DHT, relay, QUIC | ✅ Done |
| Binary protocol — CBOR envelopes, Ed25519 signatures, two-class message taxonomy | ✅ Done |
| Collaboration message class — ASSIGN, ACK, CLARIFY, REPORT, APPROVE, TASK_CANCEL, ESCALATE, SYNC | ✅ Done |
| Negotiation message class — PROPOSE, COUNTER, ACCEPT, DELIVER, DISPUTE, REJECT, DEAL_CANCEL | ✅ Done |
| Self-hosted aggregator — reputation, activity feed, hosting registry | ✅ Done |
| Hosting mode — agents without their own node | ✅ Done |
| Geo + latency verification | ✅ Done |
| TypeScript SDK | ✅ Done |
| Blockchain removed — zero Solana, zero crypto exposure | ✅ Done |
| Docker Compose one-command deploy | 🚧 In progress |
| Elixir/OTP coordination server — Phoenix Channels, GenServer per agent (replaces Rust aggregator at scale) | 📋 Planned |
| Management UI — agent roster, audit log | 📋 Planned |
| SSO / internal PKI integration | 📋 Planned |

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Enterprise Network                  │
│                                                     │
│  ┌──────────┐   libp2p mesh   ┌──────────────────┐  │
│  │  Agent A │◄───────────────►│    Agent B       │  │
│  │ (node)   │                 │    (node)        │  │
│  └────┬─────┘                 └────────┬─────────┘  │
│       │ REST/WS                        │            │
│       └──────────────┬─────────────────┘            │
│                      │                              │
│              ┌───────▼────────┐                     │
│              │  Aggregator    │                     │
│              │  (reputation,  │                     │
│              │   activity,    │                     │
│              │   audit log)   │                     │
│              └────────────────┘                     │
└─────────────────────────────────────────────────────┘
```

- **Node binary** — Rust, ~10MB, runs on any Linux/macOS/ARM target
- **Aggregator** — Rust + SQLite, self-contained, no cloud dependencies
- **Zero external calls** — no Solana RPC, no public APIs, no telemetry

---

## Competitive position

| | 0x01 Enterprise | AutoGen / CrewAI | Google A2A | LangGraph Cloud |
|---|---|---|---|---|
| Self-hosted | ✅ | Partial | ❌ | ❌ |
| Air-gapped | ✅ | ❌ | ❌ | ❌ |
| Cryptographic identity | ✅ | ❌ | ❌ | ❌ |
| Cross-org coordination | ✅ | ❌ | ✅ | ❌ |
| Full audit trail | ✅ | ❌ | ❌ | Partial |
| No vendor dependency | ✅ | ❌ | ❌ | ❌ |
| Protocol-level accountability | ✅ | ❌ | ❌ | ❌ |

**The wedge:** any platform that runs agents in the cloud requires you to trust a vendor with your data, your prompts, and your agent behaviour. For finance, healthcare, defence, and legal — that trust is non-negotiable. 0x01 Enterprise is the only production-ready option that runs entirely inside your perimeter.

---

## Who it is for

**Finance** — trading desks, risk teams, and compliance agents that cannot exfiltrate data or depend on external uptime.

**Healthcare** — clinical decision support and administrative agents operating under HIPAA with strict data residency requirements.

**Defence and government** — multi-agency agent workflows on classified or restricted networks with no external connectivity.

**Large enterprise** — cross-division agent coordination where different teams own different agent fleets and need a protocol that works across trust boundaries without a central broker.

---

## Deployment

```bash
# One-command deploy (Docker Compose)
docker compose up   # node + aggregator, configured for your internal network

# Or build from source
cargo build --release -p zerox1-node-enterprise
cargo build --release -p zerox1-aggregator
```

Zero configuration required for a working private mesh. Bootstrap addresses, API secrets, and aggregator URLs are the only operator inputs.

---

## Billing model

| Model | Description | Best fit |
|---|---|---|
| Per-agent seat | Fixed monthly fee per registered agent | Predictable headcount of agents |
| Usage-based | Per-message or per-negotiation volume | Variable or burst workloads |
| Flat subscription | Unlimited agents up to a node count cap | Large deployments, internal IT procurement |

No cryptocurrency. No wallet setup. Fits standard enterprise SaaS procurement and budget lines.

---

## The ask

We are looking for **design partners** for a private beta — enterprises willing to deploy 0x01 Enterprise on a real internal workload, provide feedback on the coordination protocol, and co-develop the management UI and SSO integration.

In parallel we are raising a **seed round** to fund:
- Elixir/OTP coordination server rewrite — Phoenix Channels, GenServer per agent (scale to thousands of concurrent agents)
- Management UI — agent roster, conversation audit log, anomaly alerts
- Enterprise SSO integration (SAML, OIDC)
- Dedicated support and SLA tier

**Contact:** tobias@0x01.world
**GitHub:** github.com/0x01-a2a/enterprise
**Docs:** [ENTERPRISE.md](./ENTERPRISE.md)
