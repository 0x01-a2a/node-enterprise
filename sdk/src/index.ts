import * as fs from 'fs'
import * as net from 'net'
import * as os from 'os'
import * as path from 'path'
import { spawn, ChildProcess } from 'child_process'
import WebSocket from 'ws'
import * as ed from '@noble/ed25519'

// ============================================================================
// Public config / types
// ============================================================================

export interface Zerox1AgentConfig {
  /**
   * 32-byte Ed25519 secret key as Uint8Array, OR a path to an existing
   * key file (raw 32 bytes). If the path does not exist, the node
   * generates a new key and writes it there.
   */
  keypair: Uint8Array | string
  /** Display name broadcast in BEACON/ADVERTISE. Default: 'zerox1-agent'. */
  name?: string
  /**
   * SATI mint address as hex (32 bytes). Required for mainnet.
   * Omit to run in dev mode (SATI checks are advisory only).
   */
  satiMint?: string
  /** Solana RPC URL. Default: mainnet-beta. */
  rpcUrl?: string
  /** Directory for per-epoch envelope logs. Default: current dir. */
  logDir?: string
  /** Additional bootstrap peer multiaddrs. */
  bootstrap?: string[]
}

export type MsgType =
  | 'ADVERTISE' | 'DISCOVER'
  | 'PROPOSE' | 'COUNTER' | 'ACCEPT' | 'REJECT'
  | 'DELIVER'
  | 'NOTARIZE_BID' | 'NOTARIZE_ASSIGN'
  | 'VERDICT'
  | 'FEEDBACK'
  | 'DISPUTE'

export interface SendParams {
  msgType: MsgType
  /** Hex-encoded 32-byte agent ID. Omit for broadcast types. */
  recipient?: string
  /** Hex-encoded 16-byte conversation ID. */
  conversationId: string
  payload: Buffer | Uint8Array
}

export interface SentConfirmation {
  nonce: number
  payloadHash: string
}

export interface FeedbackPayload {
  conversationId: string
  targetAgent: string
  score: number
  outcome: number
  isDispute: boolean
  role: number
}

export interface NotarizeBidPayload {
  bidType: number
  conversationId: string
  opaqueB64: string
}

export interface InboundEnvelope {
  msgType: MsgType
  sender: string
  recipient: string
  conversationId: string
  slot: number
  nonce: number
  payloadB64: string
  feedback?: FeedbackPayload
  notarizeBid?: NotarizeBidPayload
}

export interface SendFeedbackParams {
  conversationId: string
  targetAgent: string
  /** -100 to +100 */
  score: number
  outcome: 'negative' | 'neutral' | 'positive'
  role: 'participant' | 'notary'
}

// ============================================================================
// COUNTER negotiation types
//
// PROPOSE and COUNTER envelopes share a structured payload layout:
//
//   [bytes 0-15]  LE i128 — bid amount in USDC microunits (0 = unspecified)
//   [bytes 16..]  JSON    — {"max_rounds": u8, "message": str}        (PROPOSE)
//                           {"round": u8, "max_rounds": u8, "message": str} (COUNTER)
//
// Both sides can counter-propose up to maxRounds times (default: 2).
// The proposer gets maxRounds = 3 if their average reputation score >= 70.
// Round numbering is 1-indexed: first counter = round 1, second = round 2.
// ============================================================================

/** Decoded content of an incoming PROPOSE envelope payload. */
export interface ProposePayload {
  /** Amount in USDC microunits (e.g. 1_000_000n = 1 USDC). 0n = unspecified. */
  amount: bigint
  /** Maximum counter rounds the proposer allows. Default: 2. */
  maxRounds: number
  /** Human-readable proposal message. */
  message: string
}

/** Decoded content of an incoming COUNTER envelope payload. */
export interface CounterPayload {
  /** Counter-offered amount in USDC microunits. */
  amount: bigint
  /** Which counter round this is (1-indexed). */
  round: number
  /** Maximum rounds as originally set in the PROPOSE. */
  maxRounds: number
  /** Human-readable counter message. */
  message: string
}

export interface SendProposeParams {
  /** Hex-encoded 32-byte agent ID of the target agent. */
  recipient: string
  /**
   * 16-byte hex conversation ID. Auto-generated if omitted.
   * The returned object includes the final conversation_id used.
   */
  conversationId?: string
  /** Bid amount in USDC microunits. Default: 0n (unspecified). */
  amount?: bigint
  /**
   * Max counter rounds allowed. Default: 2.
   * Set to 3 if your average reputation score is >= 70.
   */
  maxRounds?: number
  /** Proposal text (task description, terms, etc.). */
  message: string
}

export interface SendCounterParams {
  /** Hex-encoded 32-byte agent ID of the counterparty. */
  recipient: string
  /** Conversation ID from the original PROPOSE. */
  conversationId: string
  /** Counter-offered amount in USDC microunits. */
  amount: bigint
  /** Counter round number (1-indexed). Must be <= maxRounds. */
  round: number
  /** maxRounds from the original PROPOSE. */
  maxRounds: number
  /** Explanation of your counter-offer. */
  message?: string
}

/** Decoded content of an incoming ACCEPT envelope payload. */
export interface AcceptPayload {
  /**
   * The amount being accepted in USDC microunits.
   * Matches the most-recent COUNTER amount, or the original PROPOSE amount
   * if no COUNTER was issued. Use this value for `lockPayment`.
   */
  amount: bigint
  /** Optional acceptance message. */
  message: string
}

export interface SendAcceptParams {
  /** Hex-encoded 32-byte agent ID of the agent whose offer you are accepting. */
  recipient: string
  /** Conversation ID from the original PROPOSE. */
  conversationId: string
  /**
   * The agreed amount in USDC microunits — must match the most-recent COUNTER
   * (or original PROPOSE if no COUNTER was sent). Both parties use this
   * to call `lockPayment` with the correct amount.
   */
  amount: bigint
  /** Optional acceptance message. */
  message?: string
}

export interface LockPaymentParams {
  /** Hex-encoded 32-byte agent_id of the provider who will receive payment. */
  provider: string
  /** Hex-encoded 16-byte conversation ID from the negotiation. */
  conversationId: string
  /** Amount to lock in USDC microunits (must match the ACCEPT amount). */
  amount: bigint
  /** Notary fee in USDC microunits. Default: amount / 10n. */
  notaryFee?: bigint
  /** Solana slot timeout before provider can claim without approval. Default: 1000. */
  timeoutSlots?: number
  /** Hex-encoded 32-byte agent_id of a designated notary (optional). */
  notary?: string
}

export interface ApprovePaymentParams {
  /** Hex-encoded 32-byte agent_id of the requester (payer). */
  requester: string
  /** Hex-encoded 32-byte agent_id of the provider (payee). */
  provider: string
  /** Hex-encoded 16-byte conversation ID from the negotiation. */
  conversationId: string
  /** Hex-encoded 32-byte agent_id of the notary. Defaults to this agent (self-approval). */
  notary?: string
}

// ============================================================================
// Token swap whitelist
// ============================================================================

/**
 * Default token mint addresses allowed in agent-to-agent swaps.
 * Prevents agents from being tricked into swapping into fraudulent tokens.
 *
 * Both devnet and mainnet mints are included; the node validates against
 * whichever network it is connected to.
 *
 * Override per-agent with `Zerox1Agent.setSwapWhitelist()`.
 */
export const DEFAULT_SWAP_WHITELIST: ReadonlySet<string> = new Set([
  // SOL (wrapped)
  'So11111111111111111111111111111111111111112',
  // USDC — mainnet
  'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
  // USDC — devnet
  '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU',
  // USDT — mainnet
  'Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB',
  // JUP
  'JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN',
  // BONK
  'DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263',
  // RAY
  '4k3Dyjzvzp8eMZWUXbBCjEvwSkkk59S5iCNLY3QrkX6R',
  // WIF
  'EKpQGSJtjMFqKZ9KQanSqYXRcF8fBopzLHYxdM65zcjm',
])

export interface SwapParams {
  /** Solana base58 mint address of the token to sell. */
  inputMint: string
  /** Solana base58 mint address of the token to buy. */
  outputMint: string
  /** Amount in input-token native units (e.g. lamports for SOL). */
  amount: bigint
  /** Max slippage in basis points. Default: 50 (0.5%). */
  slippageBps?: number
  /** Custom whitelist to use instead of DEFAULT_SWAP_WHITELIST. Pass an empty set to disable. */
  whitelist?: ReadonlySet<string>
}

export interface SwapResult {
  /** Input amount actually consumed (native units). */
  inAmount: bigint
  /** Output amount received (native units). */
  outAmount: bigint
  /** Transaction signature. */
  signature: string
}

// ============================================================================
// PROPOSE / COUNTER payload encode + decode helpers
// ============================================================================

function writeBidPrefix(amount: bigint): Buffer {
  const buf = Buffer.alloc(16)
  buf.writeBigUInt64LE(amount & 0xFFFFFFFFFFFFFFFFn, 0)
  buf.writeBigUInt64LE(amount >> 64n, 8)
  return buf
}

function readBidPrefix(raw: Buffer): bigint {
  const lo = raw.readBigUInt64LE(0)
  const hi = raw.readBigUInt64LE(8)
  return (hi << 64n) | lo
}

/**
 * Encode a PROPOSE payload into the structured wire format:
 * `[16-byte LE i128 amount][JSON {"max_rounds": N, "message": "..."}]`
 */
export function encodeProposePayload(
  message: string,
  amount: bigint = 0n,
  maxRounds: number = 2,
): Buffer {
  const prefix = writeBidPrefix(amount)
  const json = Buffer.from(JSON.stringify({ max_rounds: maxRounds, message }))
  return Buffer.concat([prefix, json])
}

/**
 * Encode a COUNTER payload into the structured wire format:
 * `[16-byte LE i128 amount][JSON {"round": N, "max_rounds": M, "message": "..."}]`
 */
export function encodeCounterPayload(
  amount: bigint,
  round: number,
  maxRounds: number,
  message: string = '',
): Buffer {
  const prefix = writeBidPrefix(amount)
  const json = Buffer.from(JSON.stringify({ round, max_rounds: maxRounds, message }))
  return Buffer.concat([prefix, json])
}

/**
 * Decode a PROPOSE envelope payload.
 * Returns `null` if the payload is not in the structured format
 * (e.g. a raw-string PROPOSE from an older agent).
 */
export function decodeProposePayload(payloadB64: string): ProposePayload | null {
  const raw = Buffer.from(payloadB64, 'base64')
  if (raw.length < 17 || raw[16] !== 0x7b /* '{' */) return null
  try {
    const body = JSON.parse(raw.slice(16).toString('utf8')) as Record<string, unknown>
    return {
      amount: readBidPrefix(raw),
      maxRounds: Number(body['max_rounds'] ?? 2),
      message: String(body['message'] ?? ''),
    }
  } catch {
    return null
  }
}

/**
 * Encode an ACCEPT payload.
 * `[16-byte LE i128 amount][JSON {"message": "..."}]`
 *
 * Both parties must use the same `amount` — it is the agreed price that
 * will be passed to `lockPayment` on-chain.
 */
export function encodeAcceptPayload(
  amount: bigint,
  message: string = '',
): Buffer {
  const prefix = writeBidPrefix(amount)
  const json = Buffer.from(JSON.stringify({ message }))
  return Buffer.concat([prefix, json])
}

/**
 * Decode an ACCEPT envelope payload.
 * Returns `null` if the payload is not in the structured format
 * (older agents may send a plain-text ACCEPT).
 */
export function decodeAcceptPayload(payloadB64: string): AcceptPayload | null {
  const raw = Buffer.from(payloadB64, 'base64')
  if (raw.length < 17 || raw[16] !== 0x7b /* '{' */) return null
  try {
    const body = JSON.parse(raw.slice(16).toString('utf8')) as Record<string, unknown>
    return {
      amount: readBidPrefix(raw),
      message: String(body['message'] ?? ''),
    }
  } catch {
    return null
  }
}

/**
 * Decode a COUNTER envelope payload.
 * Returns `null` if the payload is not in the structured format.
 */
export function decodeCounterPayload(payloadB64: string): CounterPayload | null {
  const raw = Buffer.from(payloadB64, 'base64')
  if (raw.length < 17 || raw[16] !== 0x7b /* '{' */) return null
  try {
    const body = JSON.parse(raw.slice(16).toString('utf8')) as Record<string, unknown>
    return {
      amount: readBidPrefix(raw),
      round: Number(body['round'] ?? 1),
      maxRounds: Number(body['max_rounds'] ?? 2),
      message: String(body['message'] ?? ''),
    }
  } catch {
    return null
  }
}

// ============================================================================
// Hosting types
// ============================================================================

export interface HostingNode {
  node_id: string
  name: string
  fee_bps: number
  api_url: string
  hosted_count: number
  first_seen: number
  last_seen: number
}

export interface HostedRegistration {
  agent_id: string
  token: string
}

export interface HostedAgentConfig {
  /** Base URL of the host node, e.g. "https://host.example.com". */
  hostApiUrl: string
  /** Bearer token returned by registerHosted(). */
  token: string
}

// ============================================================================
// Ownership types
// ============================================================================

export interface OwnerProposal {
  status: 'pending'
  agent_id: string
  proposed_owner: string
  proposed_at: number
}

export interface OwnerRecord {
  status: 'claimed'
  agent_id: string
  owner: string
  claimed_at: number
}

export interface OwnerUnclaimed {
  status: 'unclaimed'
}

export type OwnerStatus = OwnerUnclaimed | OwnerProposal | OwnerRecord

// ============================================================================
// CBOR encoding for FEEDBACK payload
//
// FEEDBACK payloads must be CBOR-encoded. Receiving nodes run
// FeedbackPayload::decode() which is a strict CBOR parser — any other
// encoding fails validation rule 9 and the message is silently dropped.
//
// Structure: CBOR array of 6 items:
//   [0] bstr(16)  conversation_id
//   [1] bstr(32)  target_agent
//   [2] int       score  (-100..100)
//   [3] uint      outcome (0..2)
//   [4] bool      is_dispute
//   [5] uint      role   (0..1)
// ============================================================================

function cborInt(n: number): Buffer {
  n = Math.trunc(n)
  if (n >= 0 && n <= 23) return Buffer.from([n])
  if (n >= 24 && n <= 255) return Buffer.from([0x18, n])
  if (n >= -24 && n < 0) return Buffer.from([0x20 + (-n - 1)])
  if (n >= -256 && n < -24) return Buffer.from([0x38, -n - 1])
  throw new RangeError(`CBOR int out of range: ${n}`)
}

function encodeFeedbackCbor(
  conversationIdHex: string,
  targetAgentHex: string,
  score: number,
  outcome: number,
  isDispute: boolean,
  role: number,
): Buffer {
  const convId = Buffer.from(conversationIdHex, 'hex') // 16 bytes
  const targetAgent = Buffer.from(targetAgentHex, 'hex') // 32 bytes
  return Buffer.concat([
    Buffer.from([0x86]),                    // array(6)
    Buffer.from([0x50]), convId,            // bytes(16)
    Buffer.from([0x58, 0x20]), targetAgent, // bytes(32)
    cborInt(score),
    cborInt(outcome),
    Buffer.from([isDispute ? 0xF5 : 0xF4]),
    cborInt(role),
  ])
}

// ============================================================================
// Binary resolution
// ============================================================================

function getBinaryPath(): string {
  const platform = process.platform // 'win32' | 'darwin' | 'linux'
  const arch = process.arch     // 'x64' | 'arm64'
  const binName = platform === 'win32' ? 'zerox1-node.exe' : 'zerox1-node'
  const pkgName = `@zerox1/sdk-${platform}-${arch}`

  try {
    const pkgJson = require.resolve(`${pkgName}/package.json`)
    return path.join(path.dirname(pkgJson), 'bin', binName)
  } catch {
    // Optional platform package not installed — fall back to PATH.
    // This allows developers to use a locally built binary during development.
    return binName
  }
}

// ============================================================================
// Port + process utilities
// ============================================================================

function getFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer()
    srv.listen(0, '127.0.0.1', () => {
      const port = (srv.address() as net.AddressInfo).port
      srv.close(() => resolve(port))
    })
    srv.on('error', reject)
  })
}

function resolveKeypairPath(keypair: Uint8Array | string): string {
  if (typeof keypair === 'string') {
    // Caller passed a file path — use it directly.
    return keypair
  }
  // Caller passed raw bytes — write to a temp file with restrictive permissions.
  // mode 0o600: owner read/write only — prevents other users from reading the key.
  // Create a private temp directory first (mode 0o700) to prevent symlink
  // race attacks on world-writable /tmp before writing the key file.
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'zerox1-'))
  fs.chmodSync(tmpDir, 0o700)
  const tmpPath = path.join(tmpDir, 'identity.key')
  fs.writeFileSync(tmpPath, Buffer.from(keypair), { mode: 0o600 })
  return tmpPath
}

async function waitForReady(port: number, timeoutMs = 15_000): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`http://127.0.0.1:${port}/peers`)
      if (res.ok) return
    } catch {
      // not ready yet
    }
    await new Promise(r => setTimeout(r, 200))
  }
  throw new Error(`zerox1-node did not become ready within ${timeoutMs}ms`)
}

// ============================================================================
// Zerox1Agent
// ============================================================================

type Handler = (env: InboundEnvelope) => void | Promise<void>

export class Zerox1Agent {
  private proc: ChildProcess | null = null
  private ws: WebSocket | null = null
  private handlers: Map<string, Handler[]> = new Map()
  private port: number = 0
  private nodeUrl: string = ''
  private _reconnectDelay: number = 1000
  private _swapWhitelist: ReadonlySet<string> = DEFAULT_SWAP_WHITELIST

  private constructor() { }

  // ── Factory ───────────────────────────────────────────────────────────────

  /**
   * Create an Zerox1Agent instance.
   * Call `agent.on(...)` to register handlers, then `agent.start()` to join
   * the mesh. The node binary is bundled — no separate install required.
   */
  static create(config: Zerox1AgentConfig): Zerox1Agent {
    const agent = new Zerox1Agent()
    agent._config = config
    return agent
  }

  /**
   * Fetch active hosting nodes from the 0x01 aggregator.
   * These are nodes that offer to relay envelopes for
   * lightweight/serverless agents that cannot run a full node.
   */
  static async listHostingNodes(
    aggregatorUrl = 'https://api.0x01.world'
  ): Promise<HostingNode[]> {
    const res = await fetch(`${aggregatorUrl}/hosting/nodes`)
    if (!res.ok) throw new Error(`Failed to fetch hosting nodes: HTTP ${res.status}`)
    return res.json() as Promise<HostingNode[]>
  }

  /**
   * Register a new hosted-agent session on a hosting node.
   * The host generates a fresh Ed25519 sub-keypair; your
   * agent_id is its public key. Keep the token secret.
   *
   * @param hostApiUrl - Base URL of the selected hosting node.
   * @returns { agent_id, token } — persist both for reconnection.
   */
  static async registerHosted(hostApiUrl: string): Promise<HostedRegistration> {
    const url = hostApiUrl.replace(/\/$/, '')
    const res = await fetch(`${url}/hosted/register`, { method: 'POST' })
    if (!res.ok) {
      const body = await res.text()
      throw new Error(`registerHosted failed (${res.status}): ${body}`)
    }
    return res.json() as Promise<HostedRegistration>
  }

  /**
   * Create a hosted agent that delegates to an existing host node.
   * No binary is spawned — the SDK connects to the host's WebSocket inbox
   * and routes outbound sends through the host.
   *
   * @param config - { hostApiUrl, token } returned from registerHosted().
   */
  static createHosted(config: HostedAgentConfig): HostedAgent {
    return new HostedAgent(config)
  }

  // ── Ownership claims ───────────────────────────────────────────────────────

  /**
   * Propose a human wallet as the owner of this agent.
   *
   * Called by the agent or its operator. The human wallet is notified
   * and can accept via `accept_claim()` in the agent-ownership Solana program,
   * then call `claimOwner()` (or POST /agents/:id/claim-owner) to confirm.
   *
   * Optional — agents without an owner are fully functional on the mesh.
   *
   * @param agentId        - Hex-encoded 64-char agent ID.
   * @param proposedOwner  - Base58 Solana wallet address of the intended human.
   * @param aggregatorUrl  - Aggregator base URL (defaults to mainnet).
   */
  static async proposeOwner(
    agentId: string,
    proposedOwner: string,
    aggregatorUrl = 'https://api.0x01.world',
  ): Promise<{ status: string; agent_id: string; proposed_owner: string }> {
    const res = await fetch(`${aggregatorUrl}/agents/${agentId}/propose-owner`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ proposed_owner: proposedOwner }),
    })
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: `HTTP ${res.status}` }))
      throw new Error(`proposeOwner failed: ${(err as { error?: string }).error ?? res.status}`)
    }
    return res.json() as Promise<{ status: string; agent_id: string; proposed_owner: string }>
  }

  /**
   * Read the current ownership status of an agent.
   *
   * Possible responses:
   *   - `{ status: "unclaimed" }`
   *   - `{ status: "pending",  proposed_owner: "7XsB...", proposed_at: 123 }`
   *   - `{ status: "claimed",  owner: "7XsB...", claimed_at: 123 }`
   *
   * @param agentId       - Hex-encoded 64-char agent ID.
   * @param aggregatorUrl - Aggregator base URL.
   */
  static async getOwner(
    agentId: string,
    aggregatorUrl = 'https://api.0x01.world',
  ): Promise<OwnerStatus> {
    const res = await fetch(`${aggregatorUrl}/agents/${agentId}/owner`)
    if (!res.ok) throw new Error(`getOwner failed: HTTP ${res.status}`)
    return res.json() as Promise<OwnerStatus>
  }

  private _config!: Zerox1AgentConfig

  // ── Lifecycle ─────────────────────────────────────────────────────────────

  /**
   * Start the node, wait for it to be ready, connect the inbox stream.
   * Safe to await — resolves once the agent is live on the mesh.
   */
  async start(): Promise<void> {
    this.port = await getFreePort()
    this.nodeUrl = `http://127.0.0.1:${this.port}`

    const keypairPath = resolveKeypairPath(this._config.keypair)
    const binaryPath = getBinaryPath()

    const args: string[] = [
      '--keypair-path', keypairPath,
      '--api-addr', `127.0.0.1:${this.port}`,
      '--agent-name', this._config.name ?? '',
    ]

    if (this._config.satiMint) args.push('--sati-mint', this._config.satiMint)
    if (this._config.rpcUrl) args.push('--rpc-url', this._config.rpcUrl)
    if (this._config.logDir) args.push('--log-dir', this._config.logDir)
    for (const b of this._config.bootstrap ?? []) {
      args.push('--bootstrap', b)
    }

    this.proc = spawn(binaryPath, args, { stdio: ['ignore', 'pipe', 'pipe'] })

    this.proc.on('error', (err) => {
      throw new Error(
        `Failed to start zerox1-node (${binaryPath}): ${err.message}\n` +
        `Make sure the binary is installed or in your PATH.`
      )
    })

    // Surface node logs prefixed so they're distinguishable in agent output.
    this.proc.stderr?.on('data', (d: Buffer) => {
      process.stderr.write(`[zerox1-node] ${d}`)
    })

    // Wait until the HTTP server is accepting connections.
    await waitForReady(this.port)

    // Fire-and-forget version check: warn if a newer SDK is available.
    this._checkVersion().catch(() => { /* never block the agent */ })

    // Open the inbox WebSocket.
    this._connectInbox()

    if (!this._config.satiMint) {
      process.stderr.write(
        `\n⚠️  [zerox1] Running in Dev Mode (no satiMint).\n` +
        `   This agent is unregistered and will be dropped by production nodes.\n\n`
      )
    }
  }

  /** Fetch /version from the aggregator and warn if this SDK is outdated. */
  private async _checkVersion(): Promise<void> {
    const AGGREGATOR = 'https://aggregator.0x01.world'
    const CURRENT = require('../package.json').version
    try {
      const res = await fetch(`${AGGREGATOR}/version`, { signal: AbortSignal.timeout(4_000) })
      if (!res.ok) return
      const { sdk } = await res.json() as { sdk: string }
      if (sdk && sdk !== CURRENT && this._isNewer(sdk, CURRENT)) {
        process.stderr.write(
          `\n⚠️  [zerox1] SDK update available: ${CURRENT} → ${sdk}\n` +
          `   Run: npm install @zerox1/sdk@latest\n\n`
        )
      }
    } catch { /* network unavailable — silently skip */ }
  }

  private _isNewer(latest: string, current: string): boolean {
    const parse = (v: string) => v.split('.').map(Number)
    const [lM, lm, lp] = parse(latest); const [cM, cm, cp] = parse(current)
    if (lM !== cM) return lM > cM
    if (lm !== cm) return lm > cm
    return lp > cp
  }

  /**
   * Disconnect from the mesh and stop the node process.
   */
  disconnect(): void {
    this.ws?.close()
    this.ws = null
    this.proc?.kill()
    this.proc = null
  }

  // ── Handlers ──────────────────────────────────────────────────────────────

  /**
   * Register a handler for a message type.
   * Use `'*'` to catch all inbound message types.
   * Chain multiple `.on()` calls — all handlers for a type are called in order.
   */
  on(msgType: MsgType | '*', handler: Handler): this {
    const key = msgType === '*' ? '__all__' : msgType
    const list = this.handlers.get(key) ?? []
    list.push(handler)
    this.handlers.set(key, list)
    return this
  }

  private _dispatch(env: InboundEnvelope): void {
    const specific = this.handlers.get(env.msgType) ?? []
    const wildcard = this.handlers.get('__all__') ?? []
    for (const h of [...specific, ...wildcard]) {
      try { void h(env) } catch { /* handler errors are isolated */ }
    }
  }

  // ── Sending ───────────────────────────────────────────────────────────────

  /**
   * Send an envelope. The node signs it and routes via libp2p.
   * Returns the assigned nonce and payload hash for tracking.
   */
  async send(params: SendParams): Promise<SentConfirmation> {
    if (!params.conversationId) {
      throw new Error(
        'conversationId is required. Generate one with agent.newConversationId().'
      )
    }
    const body = {
      msg_type: params.msgType,
      recipient: params.recipient ?? null,
      conversation_id: params.conversationId,
      payload_b64: Buffer.from(params.payload).toString('base64'),
    }

    const res = await fetch(`${this.nodeUrl}/envelopes/send`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
    const isJson = res.headers.get('content-type')?.includes('application/json')
    if (!res.ok) {
      if (isJson) {
        const errJson = await res.json() as Record<string, unknown>
        throw new Error((errJson['error'] as string) ?? `HTTP ${res.status}`)
      } else {
        const text = await res.text()
        throw new Error(text || `HTTP ${res.status}`)
      }
    }

    const json = await res.json() as Record<string, unknown>
    return {
      nonce: json['nonce'] as number,
      payloadHash: json['payload_hash'] as string,
    }
  }

  /**
   * Send a FEEDBACK envelope with CBOR-encoded payload.
   * Protocol rule 9 requires CBOR — this method handles the encoding.
   */
  async sendFeedback(params: SendFeedbackParams): Promise<SentConfirmation> {
    if (params.score < -100 || params.score > 100)
      throw new RangeError(`score must be in [-100, 100], got ${params.score}`)

    const outcomeMap = { negative: 0, neutral: 1, positive: 2 } as const
    const roleMap = { participant: 0, notary: 1 } as const

    const payload = encodeFeedbackCbor(
      params.conversationId,
      params.targetAgent,
      params.score,
      outcomeMap[params.outcome],
      false,
      roleMap[params.role],
    )

    return this.send({
      msgType: 'FEEDBACK',
      conversationId: params.conversationId,
      payload,
    })
  }

  /**
   * Send a PROPOSE envelope.
   *
   * Calls POST /negotiate/propose — the node handles binary payload encoding.
   * Returns the conversation ID used (auto-generated if not supplied)
   * along with the send confirmation.
   */
  async sendPropose(
    params: SendProposeParams
  ): Promise<{ conversationId: string; confirmation: SentConfirmation }> {
    const res = await fetch(`${this.nodeUrl}/negotiate/propose`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        recipient: params.recipient,
        conversation_id: params.conversationId,
        amount_usdc_micro: params.amount !== undefined ? Number(params.amount) : undefined,
        max_rounds: params.maxRounds,
        message: params.message,
      }),
    })
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: `HTTP ${res.status}` })) as Record<string, unknown>
      throw new Error((err['error'] as string) ?? `HTTP ${res.status}`)
    }
    const json = await res.json() as Record<string, unknown>
    return {
      conversationId: json['conversation_id'] as string,
      confirmation: { nonce: json['nonce'] as number, payloadHash: json['payload_hash'] as string },
    }
  }

  /**
   * Send a COUNTER envelope.
   *
   * Calls POST /negotiate/counter — the node handles binary payload encoding.
   * Protocol rules: `round` must be 1-indexed and <= `maxRounds`.
   */
  async sendCounter(params: SendCounterParams): Promise<SentConfirmation> {
    if (params.round < 1 || params.round > params.maxRounds) {
      throw new RangeError(`round ${params.round} is out of range [1, ${params.maxRounds}]`)
    }
    const res = await fetch(`${this.nodeUrl}/negotiate/counter`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        recipient: params.recipient,
        conversation_id: params.conversationId,
        amount_usdc_micro: Number(params.amount),
        round: params.round,
        max_rounds: params.maxRounds,
        message: params.message,
      }),
    })
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: `HTTP ${res.status}` })) as Record<string, unknown>
      throw new Error((err['error'] as string) ?? `HTTP ${res.status}`)
    }
    const json = await res.json() as Record<string, unknown>
    return { nonce: json['nonce'] as number, payloadHash: json['payload_hash'] as string }
  }

  /**
   * Send an ACCEPT envelope with the agreed amount.
   *
   * Calls POST /negotiate/accept — the node handles binary payload encoding.
   * The `amount` must match the most-recent COUNTER (or original PROPOSE if
   * there was no counter). Both parties use this value to call `lockPayment`.
   */
  async sendAccept(params: SendAcceptParams): Promise<SentConfirmation> {
    const res = await fetch(`${this.nodeUrl}/negotiate/accept`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        recipient: params.recipient,
        conversation_id: params.conversationId,
        amount_usdc_micro: Number(params.amount),
        message: params.message,
      }),
    })
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: `HTTP ${res.status}` })) as Record<string, unknown>
      throw new Error((err['error'] as string) ?? `HTTP ${res.status}`)
    }
    const json = await res.json() as Record<string, unknown>
    return { nonce: json['nonce'] as number, payloadHash: json['payload_hash'] as string }
  }

  /**
   * Lock USDC in the escrow program on-chain.
   *
   * Call this after `sendAccept()` to fund the escrow account before the
   * provider begins work. The node signs the Solana transaction using its
   * own keypair (this agent is the requester / payer).
   *
   * The automatic lock triggered by `sendAccept()` (via the node loop) uses
   * default parameters. Use this method for explicit control — e.g. a custom
   * notary or timeout.
   *
   * @param params.amount — must match the amount in the ACCEPT payload exactly.
   */
  async lockPayment(params: LockPaymentParams): Promise<void> {
    const res = await fetch(`${this.nodeUrl}/escrow/lock`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        provider: params.provider,
        conversation_id: params.conversationId,
        amount_usdc_micro: Number(params.amount),
        notary_fee: params.notaryFee !== undefined ? Number(params.notaryFee) : undefined,
        timeout_slots: params.timeoutSlots,
        notary: params.notary,
      }),
    })
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: `HTTP ${res.status}` })) as Record<string, unknown>
      throw new Error(`lockPayment failed: ${(err['error'] as string) ?? res.status}`)
    }
  }

  /**
   * Approve and release a locked escrow payment to the provider.
   *
   * Call this after verifying the provider's DELIVER output is satisfactory.
   * The node signs as the approver (notary or requester).
   *
   * @param params.notary — defaults to this agent (self-approval when no separate notary).
   */
  async approvePayment(params: ApprovePaymentParams): Promise<void> {
    const res = await fetch(`${this.nodeUrl}/escrow/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        requester: params.requester,
        provider: params.provider,
        conversation_id: params.conversationId,
        notary: params.notary,
      }),
    })
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: `HTTP ${res.status}` })) as Record<string, unknown>
      throw new Error(`approvePayment failed: ${(err['error'] as string) ?? res.status}`)
    }
  }

  // ── Token swap ────────────────────────────────────────────────────────────

  /**
   * Override the token whitelist for this agent instance.
   * Pass an empty Set to disable whitelist enforcement (not recommended).
   */
  setSwapWhitelist(whitelist: ReadonlySet<string>): void {
    this._swapWhitelist = whitelist
  }

  /**
   * Execute a Jupiter token swap via the node's `/trade/swap` endpoint.
   *
   * Both `inputMint` and `outputMint` must be in the active whitelist
   * (DEFAULT_SWAP_WHITELIST unless overridden via `setSwapWhitelist()`).
   * This prevents agents from being deceived into swapping fraudulent tokens.
   *
   * @throws If either mint is not whitelisted, or the node rejects the swap.
   */
  async swap(params: SwapParams): Promise<SwapResult> {
    const whitelist = params.whitelist ?? this._swapWhitelist
    if (whitelist.size > 0) {
      if (!whitelist.has(params.inputMint)) {
        throw new Error(`swap: inputMint ${params.inputMint} is not in the token whitelist`)
      }
      if (!whitelist.has(params.outputMint)) {
        throw new Error(`swap: outputMint ${params.outputMint} is not in the token whitelist`)
      }
    }

    const res = await fetch(`${this.nodeUrl}/trade/swap`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        input_mint: params.inputMint,
        output_mint: params.outputMint,
        amount: params.amount.toString(),
        slippage_bps: params.slippageBps ?? 50,
      }),
    })
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: `HTTP ${res.status}` })) as Record<string, unknown>
      throw new Error(`swap failed: ${(err['error'] as string) ?? res.status}`)
    }
    const data = await res.json() as { in_amount: string; out_amount: string; signature: string }
    return {
      inAmount: BigInt(data.in_amount),
      outAmount: BigInt(data.out_amount),
      signature: data.signature,
    }
  }

  // ── Utilities ─────────────────────────────────────────────────────────────

  /** Generate a random 16-byte conversation ID as hex. */
  newConversationId(): string {
    const bytes = new Uint8Array(16)
    crypto.getRandomValues(bytes)
    return Buffer.from(bytes).toString('hex')
  }

  /**
   * Encode a bid value (i128 LE) into the first 16 bytes of a payload,
   * followed by optional extra bytes (your terms).
   * @deprecated Use `encodeProposePayload()` or `encodeCounterPayload()` instead.
   */
  encodeBidValue(value: bigint, rest: Buffer = Buffer.alloc(0)): Buffer {
    const buf = Buffer.alloc(16)
    buf.writeBigInt64LE(value & 0xFFFFFFFFFFFFFFFFn, 0)
    buf.writeBigInt64LE(value >> 64n, 8)
    return Buffer.concat([buf, rest])
  }

  // ── Internal ──────────────────────────────────────────────────────────────

  private _connectInbox(): void {
    const wsUrl = `ws://127.0.0.1:${this.port}/ws/inbox`
    const ws = new WebSocket(wsUrl)
    this.ws = ws

    ws.on('open', () => { this._reconnectDelay = 1000 })

    ws.on('message', (data) => {
      try {
        const raw = JSON.parse(data.toString())
        const env: InboundEnvelope = {
          msgType: raw.msg_type,
          sender: raw.sender,
          recipient: raw.recipient,
          conversationId: raw.conversation_id,
          slot: raw.slot,
          nonce: raw.nonce,
          payloadB64: raw.payload_b64,
          feedback: raw.feedback ? {
            conversationId: raw.feedback.conversation_id,
            targetAgent: raw.feedback.target_agent,
            score: raw.feedback.score,
            outcome: raw.feedback.outcome,
            isDispute: raw.feedback.is_dispute,
            role: raw.feedback.role,
          } : undefined,
          notarizeBid: raw.notarize_bid ? {
            bidType: raw.notarize_bid.bid_type,
            conversationId: raw.notarize_bid.conversation_id,
            opaqueB64: raw.notarize_bid.opaque_b64,
          } : undefined,
        }
        this._dispatch(env)
      } catch { /* malformed — ignore */ }
    })

    ws.on('close', () => {
      // Reconnect with exponential backoff (1s → 2s → 4s … capped at 30s).
      if (this.proc) {
        setTimeout(() => { this._reconnectDelay = 1000; this._connectInbox() }, this._reconnectDelay)
        this._reconnectDelay = Math.min(this._reconnectDelay * 2, 30_000)
      }
    })

    ws.on('error', () => { /* close event handles reconnect */ })
  }

  // ── Blobs (Media Relay) ───────────────────────────────────────────────────

  /**
   * Upload a media blob to the aggregator.
   * Enforces reputation-based size limits:
   *   - Claimed/Rep 100+: 10 MB
   *   - Rep 50-99: 2 MB
   *   - Rep 10-49: 512 KB
   *
   * Every upload is signed by the agent's keypair for authentication.
   *
   * @param data - Buffer or Uint8Array of the media.
   * @param aggregatorUrl - Aggregator base URL.
   * @returns Hex-encoded CID (Keccak-256 hash).
   */
  async uploadBlob(
    data: Buffer | Uint8Array,
    aggregatorUrl = 'https://api.0x01.world'
  ): Promise<string> {
    const timestamp = Math.floor(Date.now() / 1000)
    const body = Buffer.from(data)

    // Signing payload: body + timestamp (8-byte Little Endian)
    const tsBuf = Buffer.alloc(8)
    tsBuf.writeBigUInt64LE(BigInt(timestamp), 0)
    const msg = Buffer.concat([body, tsBuf])

    const secretKeyHex = fs.readFileSync(resolveKeypairPath(this._config.keypair), 'hex')
    const secretKey = Buffer.from(secretKeyHex, 'hex').slice(0, 32)
    const pubKey = await ed.getPublicKey(secretKey)
    const signature = await ed.sign(msg, secretKey)

    // In dev mode agent_id == verifying key (same hex).
    // In SATI mode agent_id is the SATI mint address (different key).
    // The aggregator uses X-0x01-Agent-Id for reputation lookup and
    // X-0x01-Signer for signature verification — always the Ed25519 key.
    const signerHex  = Buffer.from(pubKey).toString('hex')
    const agentIdHex = this._config.satiMint ?? signerHex

    const res = await fetch(`${aggregatorUrl}/blobs`, {
      method: 'POST',
      headers: {
        'Content-Type':   'application/octet-stream',
        'X-0x01-Agent-Id': agentIdHex,
        'X-0x01-Signer':   signerHex,
        'X-0x01-Timestamp': timestamp.toString(),
        'X-0x01-Signature': Buffer.from(signature).toString('hex'),
      },
      body: body,
    })

    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: `HTTP ${res.status}` }))
      throw new Error(`uploadBlob failed: ${(err as { error?: string }).error ?? res.status}`)
    }

    const { cid } = await res.json() as { cid: string }
    return cid
  }

  /**
   * Download a media blob from the aggregator.
   *
   * @param cid - Hex-encoded CID.
   * @param aggregatorUrl - Aggregator base URL.
   */
  async downloadBlob(
    cid: string,
    aggregatorUrl = 'https://api.0x01.world'
  ): Promise<Buffer> {
    const res = await fetch(`${aggregatorUrl}/blobs/${cid}`)
    if (res.status === 404) throw new Error('Blob not found')
    if (!res.ok) throw new Error(`downloadBlob failed: HTTP ${res.status}`)

    const arrayBuffer = await res.arrayBuffer()
    return Buffer.from(arrayBuffer)
  }
}

// ============================================================================
// HostedAgent — lightweight hosted-mode client
// ============================================================================

/**
 * A hosted agent that delegates signing and routing to a host node.
 * No binary is spawned. Inbound envelopes are streamed via WebSocket;
 * outbound sends go through `POST /hosted/send` on the host.
 *
 * Obtain via `Zerox1Agent.createHosted({ hostApiUrl, token })`.
 */
export class HostedAgent {
  private ws: WebSocket | null = null
  private handlers: Map<string, Handler[]> = new Map()
  private _reconnectDelay: number = 1000
  private _running = false
  private readonly baseUrl: string
  private readonly token: string

  constructor(config: HostedAgentConfig) {
    this.baseUrl = config.hostApiUrl.replace(/\/$/, '')
    this.token = config.token
  }

  /**
   * Connect to the host node's inbox WebSocket.
   * Resolves once the connection is open.
   */
  async start(): Promise<void> {
    this._running = true
    await this._connect()
  }

  /** Disconnect from the host node. */
  disconnect(): void {
    this._running = false
    this.ws?.close()
    this.ws = null
  }

  /**
   * Register a handler for a message type.
   * Use `'*'` to catch all inbound message types.
   */
  on(msgType: MsgType | '*', handler: Handler): this {
    const key = msgType === '*' ? '__all__' : msgType
    const list = this.handlers.get(key) ?? []
    list.push(handler)
    this.handlers.set(key, list)
    return this
  }

  /**
   * Send an envelope through the host node.
   * The host signs it with this agent's sub-keypair and broadcasts via libp2p.
   */
  async send(params: SendParams): Promise<void> {
    const res = await fetch(`${this.baseUrl}/hosted/send`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.token}`,
      },
      body: JSON.stringify({
        msg_type: params.msgType,
        recipient: params.recipient ?? null,
        conversation_id: params.conversationId,
        payload_hex: Buffer.from(params.payload).toString('hex'),
      }),
    })
    if (!res.ok && res.status !== 204) {
      const body = await res.text()
      throw new Error(`hosted send failed (${res.status}): ${body}`)
    }
  }

  /**
   * Send a FEEDBACK envelope with CBOR-encoded payload.
   * Mirrors `Zerox1Agent.sendFeedback()`.
   */
  async sendFeedback(params: SendFeedbackParams): Promise<void> {
    if (params.score < -100 || params.score > 100)
      throw new RangeError(`score must be in [-100, 100], got ${params.score}`)

    const outcomeMap = { negative: 0, neutral: 1, positive: 2 } as const
    const roleMap = { participant: 0, notary: 1 } as const

    const payload = encodeFeedbackCbor(
      params.conversationId,
      params.targetAgent,
      params.score,
      outcomeMap[params.outcome],
      false,
      roleMap[params.role],
    )

    return this.send({ msgType: 'FEEDBACK', conversationId: params.conversationId, payload })
  }

  /** Send a PROPOSE envelope via POST /hosted/negotiate/propose. */
  async sendPropose(
    params: SendProposeParams
  ): Promise<{ conversationId: string }> {
    const res = await fetch(`${this.baseUrl}/hosted/negotiate/propose`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.token}`,
      },
      body: JSON.stringify({
        recipient: params.recipient,
        conversation_id: params.conversationId,
        amount_usdc_micro: params.amount !== undefined ? Number(params.amount) : undefined,
        max_rounds: params.maxRounds,
        message: params.message,
      }),
    })
    if (!res.ok) {
      const body = await res.text()
      throw new Error(`hosted propose failed (${res.status}): ${body}`)
    }
    const json = await res.json() as Record<string, unknown>
    return { conversationId: json['conversation_id'] as string }
  }

  /** Send a COUNTER envelope via POST /hosted/negotiate/counter. */
  async sendCounter(params: SendCounterParams): Promise<void> {
    if (params.round < 1 || params.round > params.maxRounds) {
      throw new RangeError(`round ${params.round} is out of range [1, ${params.maxRounds}]`)
    }
    const res = await fetch(`${this.baseUrl}/hosted/negotiate/counter`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.token}`,
      },
      body: JSON.stringify({
        recipient: params.recipient,
        conversation_id: params.conversationId,
        amount_usdc_micro: Number(params.amount),
        round: params.round,
        max_rounds: params.maxRounds,
        message: params.message,
      }),
    })
    if (!res.ok && res.status !== 204) {
      const body = await res.text()
      throw new Error(`hosted counter failed (${res.status}): ${body}`)
    }
  }

  /** Send an ACCEPT envelope via POST /hosted/negotiate/accept. */
  async sendAccept(params: SendAcceptParams): Promise<void> {
    const res = await fetch(`${this.baseUrl}/hosted/negotiate/accept`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.token}`,
      },
      body: JSON.stringify({
        recipient: params.recipient,
        conversation_id: params.conversationId,
        amount_usdc_micro: Number(params.amount),
        message: params.message,
      }),
    })
    if (!res.ok && res.status !== 204) {
      const body = await res.text()
      throw new Error(`hosted accept failed (${res.status}): ${body}`)
    }
  }

  /** Generate a random 16-byte conversation ID as hex. */
  newConversationId(): string {
    const bytes = new Uint8Array(16)
    crypto.getRandomValues(bytes)
    return Buffer.from(bytes).toString('hex')
  }

  // ── Internal ──────────────────────────────────────────────────────────────

  private async _connect(): Promise<void> {
    const wsUrl = `${this.baseUrl.replace(/^http/, 'ws')}/ws/hosted/inbox`
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(wsUrl, {
        headers: { Authorization: `Bearer ${this.token}` },
      })
      this.ws = ws

      ws.once('open', () => {
        this._reconnectDelay = 1000
        resolve()
      })
      ws.once('error', reject)

      ws.on('message', (data) => {
        try {
          const raw = JSON.parse(data.toString())
          const env: InboundEnvelope = {
            msgType: raw.msg_type,
            sender: raw.sender,
            recipient: raw.recipient,
            conversationId: raw.conversation_id,
            slot: raw.slot,
            nonce: raw.nonce,
            payloadB64: raw.payload_b64,
            feedback: raw.feedback ? {
              conversationId: raw.feedback.conversation_id,
              targetAgent: raw.feedback.target_agent,
              score: raw.feedback.score,
              outcome: raw.feedback.outcome,
              isDispute: raw.feedback.is_dispute,
              role: raw.feedback.role,
            } : undefined,
            notarizeBid: raw.notarize_bid ? {
              bidType: raw.notarize_bid.bid_type,
              conversationId: raw.notarize_bid.conversation_id,
              opaqueB64: raw.notarize_bid.opaque_b64,
            } : undefined,
          }
          this._dispatch(env)
        } catch { /* malformed — ignore */ }
      })

      ws.on('close', () => {
        if (this._running) {
          setTimeout(() => {
            this._reconnectDelay = 1000
            this._connect().catch(() => { })
          }, this._reconnectDelay)
          this._reconnectDelay = Math.min(this._reconnectDelay * 2, 30_000)
        }
      })
    })
  }

  private _dispatch(env: InboundEnvelope): void {
    const specific = this.handlers.get(env.msgType) ?? []
    const wildcard = this.handlers.get('__all__') ?? []
    for (const h of [...specific, ...wildcard]) {
      try { void h(env) } catch { /* handler errors are isolated */ }
    }
  }
}
