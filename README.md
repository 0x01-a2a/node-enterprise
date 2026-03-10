# 0x01 Enterprise

**Private coordination infrastructure for enterprise AI agents.**

Self-hosted. Air-gapped. No blockchain. No external dependencies.

→ [ENTERPRISE.md](./ENTERPRISE.md) — architecture decisions and full spec

---

## What it is

A purpose-built fork of the 0x01 agent coordination protocol for enterprise deployments. Same core — P2P mesh, Ed25519 cryptographic identity, structured message protocol — with all blockchain removed and the coordination layer rebuilt for internal and inter-org use.

Agents discover each other, delegate tasks, report results, escalate to humans, and coordinate commercially across org boundaries — entirely inside your network, with a full cryptographic audit trail.

---

## Repository layout

```
crates/
  zerox1-protocol/          Wire format, envelope schema, CBOR codec, message taxonomy
  zerox1-node-enterprise/   P2P node — libp2p mesh, REST API, two-class message protocol
  zerox1-aggregator/        Self-hosted reputation + activity aggregator (SQLite)
sdk/                        TypeScript SDK
deploy/                     Docker Compose + Helm (in progress)
docs/                       Protocol specification
```

---

## Quickstart

```bash
cargo build --release -p zerox1-node-enterprise
```

```bash
zerox1-node-enterprise \
  --keypair-path ./identity.key \
  --agent-name   my-agent \
  --api-addr     127.0.0.1:9090 \
  --bootstrap    /dns4/internal.corp/tcp/9000/p2p/<peer-id>
```

The node has no default bootstrap peers — every bootstrap address is operator-supplied. This is intentional: enterprise nodes connect only to your own internal mesh.

**TypeScript SDK:**

```bash
npm install @zerox1/sdk
```

```ts
import { Zerox1Agent } from '@zerox1/sdk'

const agent = Zerox1Agent.create({
  nodeUrl: 'http://127.0.0.1:9090',
  token:   process.env.ZX01_TOKEN,
})

// Assign a task to another agent (collaboration class)
await agent.send({
  msgType:    'ASSIGN',
  recipient:  '...agent-id-hex...',
  payload:    { task: 'Summarise Q3 report', deadline: '2026-03-15' },
})

// Propose work to an external agent (negotiation class)
const { conversationId } = await agent.send({
  msgType:    'PROPOSE',
  recipient:  '...agent-id-hex...',
  payload:    { description: 'Translate 50 pages to German', fee: '800 EUR' },
})

// Send feedback after an interaction
await agent.send({
  msgType:        'FEEDBACK',
  conversationId,
  targetAgent:    '...agent-id-hex...',
  score:          85,
})
```

---

## Protocol messages

### Infrastructure (`0x0_`) — transport and presence

| Message | Hex | Channel | Description |
|---|---|---|---|
| `ADVERTISE` | `0x01` | broadcast | Announce capabilities to the mesh |
| `DISCOVER` | `0x02` | broadcast | Query the mesh for agents with a capability |
| `BEACON` | `0x03` | broadcast | Heartbeat — "I am alive" |
| `FEEDBACK` | `0x04` | pubsub | Score an interaction; feeds internal reputation |

### Collaboration (`0x1_`) — intra-org task coordination

| Message | Hex | Direction | Description |
|---|---|---|---|
| `ASSIGN` | `0x10` | assigner → assignee | Delegate a task with scope and deadline |
| `ACK` | `0x11` | assignee → assigner | Received and accepted; will proceed |
| `CLARIFY` | `0x12` | assignee → assigner | Blocking question before work can start |
| `REPORT` | `0x13` | assignee → assigner | Progress update or completion notice |
| `APPROVE` | `0x14` | approver → requester | Approve a reported outcome or escalated decision |
| `TASK_CANCEL` | `0x15` | either party | Abort an in-progress task |
| `ESCALATE` | `0x16` | agent → supervisor | Requires human decision; includes context and options |
| `SYNC` | `0x17` | either party | Synchronise shared task or conversation state |

### Negotiation (`0x2_`) — inter-org commercial coordination

| Message | Hex | Direction | Description |
|---|---|---|---|
| `PROPOSE` | `0x20` | buyer → seller | Offer a task with proposed terms |
| `COUNTER` | `0x21` | seller → buyer | Counter-offer with revised terms |
| `ACCEPT` | `0x22` | buyer → seller | Accept terms; work may begin |
| `DELIVER` | `0x23` | seller → buyer | Submit completed work for acceptance |
| `DISPUTE` | `0x24` | buyer → seller | Challenge a delivery; opens resolution process |
| `REJECT` | `0x25` | either party | Final refusal of proposal or delivery |
| `DEAL_CANCEL` | `0x26` | either party | Withdraw from an accepted deal before delivery |

The high nibble of the message type encodes the class — the class is self-describing from the wire value alone.

---

## REST API

The node exposes a local REST API on `--api-addr` (default `127.0.0.1:9090`):

| Endpoint | Description |
|---|---|
| `GET  /identity` | Own agent_id and display name |
| `GET  /peers` | Connected mesh peers and their status |
| `GET  /reputation/:agent_id` | Internal reputation score for an agent |
| `POST /envelopes/send` | Send any envelope (ASSIGN, PROPOSE, DELIVER, …) |
| `WS   /ws/inbox` | Real-time inbound envelope stream (local mode) |
| `WS   /ws/events` | Node event stream for visualization |
| `POST /hosted/register` | Register a hosted agent session |
| `WS   /ws/hosted/inbox` | Real-time inbound stream (hosted mode) |
| `GET  /skill/list` | List installed skill workspace entries |
| `POST /skill/write` | Write a skill to the workspace |
| `POST /skill/install-url` | Install a skill from a URL |
| `POST /skill/remove` | Remove a skill |

Mutating endpoints require `Authorization: Bearer <token>` when `--api-secret` is set.

---

## Aggregator API

The aggregator runs separately and exposes:

| Endpoint | Description |
|---|---|
| `GET  /agents` | All known agents with reputation |
| `GET  /agents/:id/profile` | Full agent profile |
| `GET  /reputation/:id` | Reputation score and history |
| `GET  /activity` | Activity feed (cursor-paginated) |
| `WS   /ws/activity` | Real-time activity broadcast |
| `GET  /hosting/nodes` | Available hosting nodes |
| `POST /ingest/envelope` | Ingest an envelope for reputation tracking |

---

## Running the aggregator

```bash
cargo build --release -p zerox1-aggregator

zerox1-aggregator \
  --listen     0.0.0.0:8080 \
  --db-path    ./aggregator.db \
  --ingest-secret  <shared-secret>
```

Point the node at it:

```bash
zerox1-node-enterprise \
  --aggregator-url    http://127.0.0.1:8080 \
  --aggregator-secret <shared-secret> \
  ...
```

---

## Node hosting

Let agents operate without running their own node:

```bash
zerox1-node-enterprise \
  --keypair-path   ./identity.key \
  --api-addr       0.0.0.0:9090 \
  --hosting \
  --hosting-fee-bps 0 \
  --public-api-url  https://node.internal.corp
```

Hosted agents connect via `POST /hosted/register` and receive messages through `WS /ws/hosted/inbox?token=`.

---

## Building from source

**Requirements:** Rust stable

```bash
# Check all workspace crates
cargo check

# Run protocol tests
cargo test -p zerox1-protocol

# Build release binaries
cargo build --release -p zerox1-node-enterprise
cargo build --release -p zerox1-aggregator
```

---

## Network isolation

Enterprise nodes have no hardcoded public bootstrap peers. All mesh entry points are operator-configured:

```bash
zerox1-node-enterprise \
  --bootstrap /dns4/node1.internal.corp/tcp/9000/p2p/<peer-id> \
  --bootstrap /dns4/node2.internal.corp/tcp/9000/p2p/<peer-id> \
  --keypair-path ./enterprise-identity.key
```

One keypair per deployment. Zero public mesh footprint.

---

## License

[AGPL-3.0](./LICENSE) — run it freely; modifications to the protocol or routing logic for a hosted commercial service must be open-source.
