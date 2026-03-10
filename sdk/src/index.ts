import * as fs from 'fs';
import * as net from 'net';
import * as os from 'os';
import * as path from 'path';
import * as crypto from 'crypto';
import { spawn, ChildProcess } from 'child_process';
import WebSocket from 'ws';

// ============================================================================
// Types
// ============================================================================

export interface AgentConfig {
  /** 32-byte Ed25519 secret key as Uint8Array, OR a path to an existing key file. */
  keypair: Uint8Array | string;
  /** Display name broadcast in BEACON/ADVERTISE. Default: 'zerox1-agent'. */
  name?: string;
  /** Additional bootstrap peer multiaddrs. */
  bootstrap?: string[];
  /** Aggregator URL for reputation lookups. Default: http://127.0.0.1:8080 */
  aggregatorUrl?: string;
  /** Bearer token required by the node REST API when --api-secret is set. */
  apiSecret?: string;
}

// Infrastructure (0x0_)
export type MsgType =
  | 'ADVERTISE'
  | 'DISCOVER'
  | 'BEACON'
  | 'FEEDBACK'
  // Collaboration (0x1_) - intra-org
  | 'ASSIGN'
  | 'ACK'
  | 'CLARIFY'
  | 'REPORT'
  | 'APPROVE'
  | 'TASK_CANCEL'
  | 'ESCALATE'
  | 'SYNC'
  // Negotiation (0x2_) - inter-org
  | 'PROPOSE'
  | 'COUNTER'
  | 'ACCEPT'
  | 'DELIVER'
  | 'DISPUTE'
  | 'REJECT'
  | 'DEAL_CANCEL';

export interface SendParams {
  msgType: MsgType;
  /** Hex-encoded 32-byte agent ID. Omit for broadcast types. */
  recipient?: string;
  /** Hex-encoded 16-byte conversation ID. */
  conversationId: string;
  payload: Buffer | Uint8Array;
}

export interface SentConfirmation {
  nonce: number;
  payloadHash: string;
}

export interface FeedbackPayload {
  conversationId: string;
  targetAgent: string;
  score: number;
  outcome: number;
  isDispute: boolean;
}

export interface InboundEnvelope {
  msgType: MsgType;
  sender: string;
  recipient: string;
  conversationId: string;
  slot: number;
  nonce: number;
  payloadB64: string;
  feedback?: FeedbackPayload;
}

export interface SendFeedbackParams {
  conversationId: string;
  targetAgent: string;
  /** -100 to +100 */
  score: number;
  outcome: 'negative' | 'neutral' | 'positive';
}

// ============================================================================
// Collaboration message payloads
// ============================================================================

export interface AssignPayload {
  task: string;
  inputs?: Record<string, unknown>;
  deadline?: string;
  priority?: number;
}

export interface ReportPayload {
  status: 'progress' | 'complete' | 'blocked';
  message?: string;
  outputs?: Record<string, unknown>;
}

export interface EscalatePayload {
  reason: string;
  context: Record<string, unknown>;
  options: string[];
}

export interface SyncPayload {
  state: Record<string, unknown>;
}

export interface ClarifyPayload {
  question: string;
}

// ============================================================================
// Negotiation message payloads
// ============================================================================

export interface ProposePayload {
  description: string;
  fee?: string;
  deadline?: string;
}

export interface CounterPayload {
  description: string;
  fee?: string;
  counterReason?: string;
}

export interface DeliverPayload {
  summary: string;
  outputs: Record<string, unknown>;
}

export interface DisputePayload {
  reason: string;
  evidence?: Record<string, unknown>;
}

export interface RejectPayload {
  reason: string;
}

export interface DealCancelPayload {
  reason: string;
}

// ============================================================================
// Hosted agent types
// ============================================================================

export interface HostingNode {
  node_id: string;
  name: string;
  fee_bps: number;
  api_url: string;
  hosted_count: number;
}

export interface HostedRegistration {
  agent_id: string;
  token: string;
}

export interface HostedAgentConfig {
  hostApiUrl: string;
  token: string;
}

// ============================================================================
// Encoding helpers
// ============================================================================

export function encodeAssignPayload(task: string, inputs?: Record<string, unknown>, deadline?: string, priority?: number): Buffer {
  return Buffer.from(JSON.stringify({ task, inputs, deadline, priority }));
}

export function encodeReportPayload(status: 'progress' | 'complete' | 'blocked', message?: string, outputs?: Record<string, unknown>): Buffer {
  return Buffer.from(JSON.stringify({ status, message, outputs }));
}

export function encodeEscalatePayload(reason: string, context: Record<string, unknown>, options: string[]): Buffer {
  return Buffer.from(JSON.stringify({ reason, context, options }));
}

export function encodeSyncPayload(state: Record<string, unknown>): Buffer {
  return Buffer.from(JSON.stringify({ state }));
}

export function encodeProposePayload(description: string, fee?: string, deadline?: string): Buffer {
  return Buffer.from(JSON.stringify({ description, fee, deadline }));
}

export function encodeCounterPayload(description: string, fee?: string, counterReason?: string): Buffer {
  return Buffer.from(JSON.stringify({ description, fee, counterReason }));
}

export function encodeAcceptPayload(): Buffer {
  return Buffer.from(JSON.stringify({}));
}

export function encodeDeliverPayload(summary: string, outputs: Record<string, unknown>): Buffer {
  return Buffer.from(JSON.stringify({ summary, outputs }));
}

export function encodeDisputePayload(reason: string, evidence?: Record<string, unknown>): Buffer {
  return Buffer.from(JSON.stringify({ reason, evidence }));
}

export function encodeRejectPayload(reason: string): Buffer {
  return Buffer.from(JSON.stringify({ reason }));
}

export function encodeDealCancelPayload(reason: string): Buffer {
  return Buffer.from(JSON.stringify({ reason }));
}

export function encodeClarifyPayload(question: string): Buffer {
  return Buffer.from(JSON.stringify({ question }));
}

export function decodePayload<T = Record<string, unknown>>(payloadB64: string): T | null {
  try {
    return JSON.parse(Buffer.from(payloadB64, 'base64').toString('utf8')) as T;
  } catch {
    return null;
  }
}

// ============================================================================
// CBOR encoding for FEEDBACK payload
// ============================================================================

function cborInt(n: number): Buffer {
  n = Math.trunc(n);
  if (n >= 0 && n <= 23) return Buffer.from([n]);
  if (n >= 24 && n <= 255) return Buffer.from([0x18, n]);
  if (n >= -24 && n < 0) return Buffer.from([0x20 + (-n - 1)]);
  if (n >= -256 && n < -24) return Buffer.from([0x38, -n - 1]);
  throw new RangeError(`CBOR int out of range: ${n}`);
}

function encodeFeedbackCbor(
  conversationIdHex: string,
  targetAgentHex: string,
  score: number,
  outcome: number,
  isDispute: boolean,
): Buffer {
  const convId = Buffer.from(conversationIdHex, 'hex');
  const targetAgent = Buffer.from(targetAgentHex, 'hex');
  return Buffer.concat([
    Buffer.from([0x85]), // array(5)
    Buffer.from([0x50]), convId,
    Buffer.from([0x58, 0x20]), targetAgent,
    cborInt(score),
    cborInt(outcome),
    Buffer.from([isDispute ? 0xf5 : 0xf4]),
  ]);
}

// ============================================================================
// Internal helpers
// ============================================================================

function getFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const port = (srv.address() as net.AddressInfo).port;
      srv.close(() => resolve(port));
    });
    srv.on('error', reject);
  });
}

function resolveKeypairPath(keypair: Uint8Array | string): string {
  if (typeof keypair === 'string') {
    return keypair;
  }
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'zx01-'));
  fs.chmodSync(tmpDir, 0o700);
  const tmpPath = path.join(tmpDir, 'identity.key');
  fs.writeFileSync(tmpPath, Buffer.from(keypair), { mode: 0o600 });
  return tmpPath;
}

async function waitForReady(port: number, timeoutMs = 15_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`http://127.0.0.1:${port}/peers`);
      if (res.ok) return;
    } catch {
      // not ready yet
    }
    await new Promise(r => setTimeout(r, 200));
  }
  throw new Error(`zerox1-node-enterprise did not become ready within ${timeoutMs}ms`);
}

// ============================================================================
// Zerox1Agent
// ============================================================================

type Handler = (env: InboundEnvelope) => void | Promise<void>;

export class Zerox1Agent {
  private proc: ChildProcess | null = null;
  private ws: WebSocket | null = null;
  private handlers: Map<string, Handler[]> = new Map();
  private port: number = 0;
  private nodeUrl: string = '';
  private _reconnectDelay: number = 1000;
  private _config!: AgentConfig;

  private constructor() {}

  static create(config: AgentConfig): Zerox1Agent {
    const agent = new Zerox1Agent();
    agent._config = config;
    return agent;
  }

  static async listHostingNodes(aggregatorUrl = 'http://127.0.0.1:8080'): Promise<HostingNode[]> {
    const res = await fetch(`${aggregatorUrl}/hosting/nodes`);
    if (!res.ok) throw new Error(`Failed to fetch hosting nodes: HTTP ${res.status}`);
    return res.json() as Promise<HostingNode[]>;
  }

  static async registerHosted(hostApiUrl: string): Promise<HostedRegistration> {
    const url = hostApiUrl.replace(/\/$/, '');
    const res = await fetch(`${url}/hosted/register`, { method: 'POST' });
    if (!res.ok) {
      const body = await res.text();
      throw new Error(`registerHosted failed (${res.status}): ${body}`);
    }
    return res.json() as Promise<HostedRegistration>;
  }

  static createHosted(config: HostedAgentConfig): HostedAgent {
    return new HostedAgent(config);
  }

  async start(): Promise<void> {
    this.port = await getFreePort();
    this.nodeUrl = `http://127.0.0.1:${this.port}`;

    const keypairPath = resolveKeypairPath(this._config.keypair);

    const args: string[] = [
      '--keypair-path', keypairPath,
      '--api-addr', `127.0.0.1:${this.port}`,
      '--agent-name', this._config.name ?? '',
    ];

    if (this._config.aggregatorUrl) {
      args.push('--aggregator-url', this._config.aggregatorUrl);
    }

    for (const b of this._config.bootstrap ?? []) {
      args.push('--bootstrap', b);
    }

    if (this._config.apiSecret) {
      args.push('--api-secret', this._config.apiSecret);
    }

    this.proc = spawn('zerox1-node-enterprise', args, { stdio: ['ignore', 'pipe', 'pipe'] });

    this.proc.on('error', (err) => {
      throw new Error(`Failed to start zerox1-node-enterprise: ${err.message}`);
    });

    this.proc.stderr?.on('data', (d: Buffer) => {
      process.stderr.write(`[zerox1-node-enterprise] ${d}`);
    });

    await waitForReady(this.port);
    this._connectInbox();
  }

  disconnect(): void {
    this.ws?.close();
    this.ws = null;
    this.proc?.kill();
    this.proc = null;
  }

  on(msgType: MsgType | '*', handler: Handler): this {
    const key = msgType === '*' ? '__all__' : msgType;
    const list = this.handlers.get(key) ?? [];
    list.push(handler);
    this.handlers.set(key, list);
    return this;
  }

  private _dispatch(env: InboundEnvelope): void {
    const specific = this.handlers.get(env.msgType) ?? [];
    const wildcard = this.handlers.get('__all__') ?? [];
    for (const h of [...specific, ...wildcard]) {
      try { void h(env); } catch { /* handler errors are isolated */ }
    }
  }

  async send(params: SendParams): Promise<SentConfirmation> {
    if (!params.conversationId) {
      throw new Error('conversationId is required');
    }

    const body = {
      msg_type: params.msgType,
      recipient: params.recipient ?? null,
      conversation_id: params.conversationId,
      payload_b64: Buffer.from(params.payload).toString('base64'),
    };

    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (this._config.apiSecret) {
      headers['Authorization'] = `Bearer ${this._config.apiSecret}`;
    }

    const res = await fetch(`${this.nodeUrl}/envelopes/send`, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
      throw new Error((err as { error?: string }).error ?? `HTTP ${res.status}`);
    }

    const json = await res.json() as Record<string, unknown>;
    return {
      nonce: json['nonce'] as number,
      payloadHash: json['payload_hash'] as string,
    };
  }

  async sendFeedback(params: SendFeedbackParams): Promise<SentConfirmation> {
    if (params.score < -100 || params.score > 100) {
      throw new RangeError(`score must be in [-100, 100], got ${params.score}`);
    }

    const outcomeMap = { negative: 0, neutral: 1, positive: 2 } as const;

    const payload = encodeFeedbackCbor(
      params.conversationId,
      params.targetAgent,
      params.score,
      outcomeMap[params.outcome],
      false,
    );

    return this.send({
      msgType: 'FEEDBACK',
      conversationId: params.conversationId,
      payload,
    });
  }

  // Collaboration message helpers
  async sendAssign(recipient: string, conversationId: string, task: string, inputs?: Record<string, unknown>, deadline?: string, priority?: number): Promise<SentConfirmation> {
    return this.send({ msgType: 'ASSIGN', recipient, conversationId, payload: encodeAssignPayload(task, inputs, deadline, priority) });
  }

  async sendAck(recipient: string, conversationId: string): Promise<SentConfirmation> {
    return this.send({ msgType: 'ACK', recipient, conversationId, payload: Buffer.from('{}') });
  }

  async sendClarify(recipient: string, conversationId: string, question: string): Promise<SentConfirmation> {
    return this.send({ msgType: 'CLARIFY', recipient, conversationId, payload: encodeClarifyPayload(question) });
  }

  async sendReport(recipient: string, conversationId: string, status: 'progress' | 'complete' | 'blocked', message?: string, outputs?: Record<string, unknown>): Promise<SentConfirmation> {
    return this.send({ msgType: 'REPORT', recipient, conversationId, payload: encodeReportPayload(status, message, outputs) });
  }

  async sendApprove(recipient: string, conversationId: string): Promise<SentConfirmation> {
    return this.send({ msgType: 'APPROVE', recipient, conversationId, payload: Buffer.from('{}') });
  }

  async sendTaskCancel(recipient: string, conversationId: string, reason?: string): Promise<SentConfirmation> {
    return this.send({ msgType: 'TASK_CANCEL', recipient, conversationId, payload: Buffer.from(JSON.stringify({ reason })) });
  }

  async sendEscalate(recipient: string, conversationId: string, reason: string, context: Record<string, unknown>, options: string[]): Promise<SentConfirmation> {
    return this.send({ msgType: 'ESCALATE', recipient, conversationId, payload: encodeEscalatePayload(reason, context, options) });
  }

  async sendSync(recipient: string, conversationId: string, state: Record<string, unknown>): Promise<SentConfirmation> {
    return this.send({ msgType: 'SYNC', recipient, conversationId, payload: encodeSyncPayload(state) });
  }

  // Negotiation message helpers
  async sendPropose(recipient: string, conversationId: string, description: string, fee?: string, deadline?: string): Promise<SentConfirmation> {
    return this.send({ msgType: 'PROPOSE', recipient, conversationId, payload: encodeProposePayload(description, fee, deadline) });
  }

  async sendCounter(recipient: string, conversationId: string, description: string, fee?: string, counterReason?: string): Promise<SentConfirmation> {
    return this.send({ msgType: 'COUNTER', recipient, conversationId, payload: encodeCounterPayload(description, fee, counterReason) });
  }

  async sendAccept(recipient: string, conversationId: string): Promise<SentConfirmation> {
    return this.send({ msgType: 'ACCEPT', recipient, conversationId, payload: encodeAcceptPayload() });
  }

  async sendDeliver(recipient: string, conversationId: string, summary: string, outputs: Record<string, unknown>): Promise<SentConfirmation> {
    return this.send({ msgType: 'DELIVER', recipient, conversationId, payload: encodeDeliverPayload(summary, outputs) });
  }

  async sendDispute(recipient: string, conversationId: string, reason: string, evidence?: Record<string, unknown>): Promise<SentConfirmation> {
    return this.send({ msgType: 'DISPUTE', recipient, conversationId, payload: encodeDisputePayload(reason, evidence) });
  }

  async sendReject(recipient: string, conversationId: string, reason: string): Promise<SentConfirmation> {
    return this.send({ msgType: 'REJECT', recipient, conversationId, payload: encodeRejectPayload(reason) });
  }

  async sendDealCancel(recipient: string, conversationId: string, reason: string): Promise<SentConfirmation> {
    return this.send({ msgType: 'DEAL_CANCEL', recipient, conversationId, payload: encodeDealCancelPayload(reason) });
  }

  newConversationId(): string {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return Buffer.from(bytes).toString('hex');
  }

  private _connectInbox(): void {
    const wsUrl = `ws://127.0.0.1:${this.port}/ws/inbox`;
    const ws = new WebSocket(wsUrl);
    this.ws = ws;

    ws.on('open', () => { this._reconnectDelay = 1000; });

    ws.on('message', (data) => {
      try {
        const raw = JSON.parse(data.toString());
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
          } : undefined,
        };
        this._dispatch(env);
      } catch { /* malformed — ignore */ }
    });

    ws.on('close', () => {
      if (this.proc) {
        setTimeout(() => { this._reconnectDelay = 1000; this._connectInbox(); }, this._reconnectDelay);
        this._reconnectDelay = Math.min(this._reconnectDelay * 2, 30_000);
      }
    });

    ws.on('error', () => { /* close event handles reconnect */ });
  }
}

// ============================================================================
// HostedAgent
// ============================================================================

export class HostedAgent {
  private ws: WebSocket | null = null;
  private handlers: Map<string, Handler[]> = new Map();
  private _reconnectDelay: number = 1000;
  private _running = false;
  private readonly baseUrl: string;
  private readonly token: string;

  constructor(config: HostedAgentConfig) {
    this.baseUrl = config.hostApiUrl.replace(/\/$/, '');
    this.token = config.token;
  }

  async start(): Promise<void> {
    this._running = true;
    await this._connect();
  }

  disconnect(): void {
    this._running = false;
    this.ws?.close();
    this.ws = null;
  }

  on(msgType: MsgType | '*', handler: Handler): this {
    const key = msgType === '*' ? '__all__' : msgType;
    const list = this.handlers.get(key) ?? [];
    list.push(handler);
    this.handlers.set(key, list);
    return this;
  }

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
    });
    if (!res.ok && res.status !== 204) {
      const body = await res.text();
      throw new Error(`hosted send failed (${res.status}): ${body}`);
    }
  }

  async sendFeedback(params: SendFeedbackParams): Promise<void> {
    if (params.score < -100 || params.score > 100) {
      throw new RangeError(`score must be in [-100, 100], got ${params.score}`);
    }

    const outcomeMap = { negative: 0, neutral: 1, positive: 2 } as const;
    const payload = encodeFeedbackCbor(
      params.conversationId,
      params.targetAgent,
      params.score,
      outcomeMap[params.outcome],
      false,
    );

    return this.send({ msgType: 'FEEDBACK', conversationId: params.conversationId, payload });
  }

  // Collaboration message helpers
  async sendAssign(recipient: string, conversationId: string, task: string, inputs?: Record<string, unknown>, deadline?: string, priority?: number): Promise<void> {
    return this.send({ msgType: 'ASSIGN', recipient, conversationId, payload: encodeAssignPayload(task, inputs, deadline, priority) });
  }

  async sendAck(recipient: string, conversationId: string): Promise<void> {
    return this.send({ msgType: 'ACK', recipient, conversationId, payload: Buffer.from('{}') });
  }

  async sendClarify(recipient: string, conversationId: string, question: string): Promise<void> {
    return this.send({ msgType: 'CLARIFY', recipient, conversationId, payload: encodeClarifyPayload(question) });
  }

  async sendReport(recipient: string, conversationId: string, status: 'progress' | 'complete' | 'blocked', message?: string, outputs?: Record<string, unknown>): Promise<void> {
    return this.send({ msgType: 'REPORT', recipient, conversationId, payload: encodeReportPayload(status, message, outputs) });
  }

  async sendApprove(recipient: string, conversationId: string): Promise<void> {
    return this.send({ msgType: 'APPROVE', recipient, conversationId, payload: Buffer.from('{}') });
  }

  async sendTaskCancel(recipient: string, conversationId: string, reason?: string): Promise<void> {
    return this.send({ msgType: 'TASK_CANCEL', recipient, conversationId, payload: Buffer.from(JSON.stringify({ reason })) });
  }

  async sendEscalate(recipient: string, conversationId: string, reason: string, context: Record<string, unknown>, options: string[]): Promise<void> {
    return this.send({ msgType: 'ESCALATE', recipient, conversationId, payload: encodeEscalatePayload(reason, context, options) });
  }

  async sendSync(recipient: string, conversationId: string, state: Record<string, unknown>): Promise<void> {
    return this.send({ msgType: 'SYNC', recipient, conversationId, payload: encodeSyncPayload(state) });
  }

  // Negotiation message helpers
  async sendPropose(recipient: string, conversationId: string, description: string, fee?: string, deadline?: string): Promise<void> {
    return this.send({ msgType: 'PROPOSE', recipient, conversationId, payload: encodeProposePayload(description, fee, deadline) });
  }

  async sendCounter(recipient: string, conversationId: string, description: string, fee?: string, counterReason?: string): Promise<void> {
    return this.send({ msgType: 'COUNTER', recipient, conversationId, payload: encodeCounterPayload(description, fee, counterReason) });
  }

  async sendAccept(recipient: string, conversationId: string): Promise<void> {
    return this.send({ msgType: 'ACCEPT', recipient, conversationId, payload: encodeAcceptPayload() });
  }

  async sendDeliver(recipient: string, conversationId: string, summary: string, outputs: Record<string, unknown>): Promise<void> {
    return this.send({ msgType: 'DELIVER', recipient, conversationId, payload: encodeDeliverPayload(summary, outputs) });
  }

  async sendDispute(recipient: string, conversationId: string, reason: string, evidence?: Record<string, unknown>): Promise<void> {
    return this.send({ msgType: 'DISPUTE', recipient, conversationId, payload: encodeDisputePayload(reason, evidence) });
  }

  async sendReject(recipient: string, conversationId: string, reason: string): Promise<void> {
    return this.send({ msgType: 'REJECT', recipient, conversationId, payload: encodeRejectPayload(reason) });
  }

  async sendDealCancel(recipient: string, conversationId: string, reason: string): Promise<void> {
    return this.send({ msgType: 'DEAL_CANCEL', recipient, conversationId, payload: encodeDealCancelPayload(reason) });
  }

  newConversationId(): string {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return Buffer.from(bytes).toString('hex');
  }

  private async _connect(): Promise<void> {
    const wsUrl = `${this.baseUrl.replace(/^http/, 'ws')}/ws/hosted/inbox`;
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(wsUrl, {
        headers: { 'Authorization': `Bearer ${this.token}` },
      });
      this.ws = ws;

      ws.once('open', () => {
        this._reconnectDelay = 1000;
        resolve();
      });
      ws.once('error', reject);

      ws.on('message', (data) => {
        try {
          const raw = JSON.parse(data.toString());
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
            } : undefined,
          };
          this._dispatch(env);
        } catch { /* malformed — ignore */ }
      });

      ws.on('close', () => {
        if (this._running) {
          setTimeout(() => {
            this._reconnectDelay = 1000;
            this._connect().catch(() => {});
          }, this._reconnectDelay);
          this._reconnectDelay = Math.min(this._reconnectDelay * 2, 30_000);
        }
      });
    });
  }

  private _dispatch(env: InboundEnvelope): void {
    const specific = this.handlers.get(env.msgType) ?? [];
    const wildcard = this.handlers.get('__all__') ?? [];
    for (const h of [...specific, ...wildcard]) {
      try { void h(env); } catch { /* handler errors are isolated */ }
    }
  }
}

// ============================================================================
// AggregatorClient — reputation, activity feed, and blob storage
// ============================================================================

export interface BlobMeta {
  cid: string;
  filename: string;
  content_type: string;
  size?: number;
  uploader?: string;
}

export interface UploadBlobResult extends BlobMeta {}

export interface AgentReputation {
  agent_id: string;
  name: string;
  feedback_count: number;
  total_score: number;
  positive_count: number;
  neutral_count: number;
  negative_count: number;
  average_score: number;
  last_updated: number;
  last_seen: number;
  /** "rising" | "falling" | "stable" */
  trend: string;
  country?: string;
  city?: string;
  latency?: Record<string, number>;
  geo_consistent?: boolean;
}

export interface AgentCapability {
  capability: string;
  count: number;
}

export interface AgentProfile {
  agent_id: string;
  name?: string;
  reputation: AgentReputation;
  capabilities: AgentCapability[];
  last_seen?: number;
}

export interface ActivityEvent {
  id: number;
  ts: number;
  /** "JOIN" | "FEEDBACK" | "DISPUTE" | "REJECT" | "DELIVER" | "ASSIGN" | "REPORT" */
  event_type: string;
  agent_id: string;
  target_id?: string;
  score?: number;
  name?: string;
  target_name?: string;
  slot?: number;
  conversation_id?: string;
}

export interface ActivityPage {
  events: ActivityEvent[];
  /** Pass as `before` to fetch the next page. Undefined when no more pages. */
  cursor?: number;
}

type ActivityHandler = (event: ActivityEvent) => void | Promise<void>;

export class AggregatorClient {
  private readonly baseUrl: string;
  private readonly apiKey?: string;
  private _activityWs: WebSocket | null = null;
  private _activityHandlers: ActivityHandler[] = [];
  private _reconnectDelay = 1000;
  private _subscribed = false;

  /**
   * @param aggregatorUrl Base URL of the aggregator. Default: http://127.0.0.1:8080
   * @param apiKey        API key for gated endpoints (reputation, leaderboard, etc).
   *                      Pass the same key set via AGGREGATOR_API_KEYS on the server.
   *                      Also used as the Bearer token for WS /ws/activity when
   *                      the aggregator has --ingest-secret configured.
   */
  constructor(aggregatorUrl = 'http://127.0.0.1:8080', apiKey?: string) {
    this.baseUrl = aggregatorUrl.replace(/\/$/, '');
    this.apiKey = apiKey;
  }

  private _authHeaders(): Record<string, string> {
    return this.apiKey ? { 'Authorization': `Bearer ${this.apiKey}` } : {};
  }

  async getAgents(params?: { country?: string; limit?: number; offset?: number; sort?: string }): Promise<AgentReputation[]> {
    const qs = new URLSearchParams();
    if (params?.country) qs.set('country', params.country);
    if (params?.limit !== undefined) qs.set('limit', String(params.limit));
    if (params?.offset !== undefined) qs.set('offset', String(params.offset));
    if (params?.sort) qs.set('sort', params.sort);
    const suffix = qs.toString() ? `?${qs}` : '';
    const res = await fetch(`${this.baseUrl}/agents${suffix}`);
    if (!res.ok) throw new Error(`getAgents failed: HTTP ${res.status}`);
    return res.json() as Promise<AgentReputation[]>;
  }

  async getAgentProfile(agentId: string): Promise<AgentProfile> {
    const res = await fetch(`${this.baseUrl}/agents/${agentId}/profile`);
    if (!res.ok) throw new Error(`getAgentProfile failed: HTTP ${res.status}`);
    return res.json() as Promise<AgentProfile>;
  }

  /** Requires apiKey — endpoint is API-key gated on the aggregator. */
  async getReputation(agentId: string): Promise<AgentReputation> {
    const res = await fetch(`${this.baseUrl}/reputation/${agentId}`, {
      headers: this._authHeaders(),
    });
    if (!res.ok) throw new Error(`getReputation failed: HTTP ${res.status}`);
    return res.json() as Promise<AgentReputation>;
  }

  async getActivity(params?: { limit?: number; before?: number }): Promise<ActivityPage> {
    const qs = new URLSearchParams();
    if (params?.limit !== undefined) qs.set('limit', String(params.limit));
    if (params?.before !== undefined) qs.set('before', String(params.before));
    const suffix = qs.toString() ? `?${qs}` : '';
    const res = await fetch(`${this.baseUrl}/activity${suffix}`);
    if (!res.ok) throw new Error(`getActivity failed: HTTP ${res.status}`);
    const events = await res.json() as ActivityEvent[];
    const cursor = events.length > 0 ? events[events.length - 1]!.id : undefined;
    return { events, cursor };
  }

  /** Subscribe to the real-time activity feed. Returns a cleanup function. */
  subscribeActivity(handler: ActivityHandler): () => void {
    this._activityHandlers.push(handler);
    if (!this._subscribed) {
      this._subscribed = true;
      this._connectActivity();
    }
    return () => {
      this._activityHandlers = this._activityHandlers.filter(h => h !== handler);
      if (this._activityHandlers.length === 0) {
        this._subscribed = false;
        this._activityWs?.close();
        this._activityWs = null;
      }
    };
  }

  private _connectActivity(): void {
    const base = this.baseUrl.replace(/^http/, 'ws');
    const wsUrl = this.apiKey
      ? `${base}/ws/activity?token=${encodeURIComponent(this.apiKey)}`
      : `${base}/ws/activity`;
    const ws = new WebSocket(wsUrl);
    this._activityWs = ws;

    ws.on('open', () => { this._reconnectDelay = 1000; });

    ws.on('message', (data) => {
      try {
        const event = JSON.parse(data.toString()) as ActivityEvent;
        for (const h of this._activityHandlers) {
          try { void h(event); } catch { /* isolated */ }
        }
      } catch { /* malformed — ignore */ }
    });

    ws.on('close', () => {
      if (this._subscribed) {
        setTimeout(() => { this._reconnectDelay = 1000; this._connectActivity(); }, this._reconnectDelay);
        this._reconnectDelay = Math.min(this._reconnectDelay * 2, 30_000);
      }
    });

    ws.on('error', () => { /* close event handles reconnect */ });
  }

  /**
   * Upload a file blob to the aggregator.
   * Authenticated with the agent's Ed25519 signing key — no API key required.
   *
   * @param signingKeyHex  64-char hex Ed25519 signing key (first 32 bytes = private scalar).
   * @param agentIdHex     64-char hex agent ID (verifying key).
   * @param data           File content.
   * @param filename       Original filename (e.g. "report.pdf").
   * @param contentType    MIME type. Defaults to application/octet-stream.
   */
  async uploadBlob(
    signingKeyHex: string,
    agentIdHex: string,
    data: Buffer | Uint8Array,
    filename = '',
    contentType = 'application/octet-stream',
  ): Promise<UploadBlobResult> {
    const buf = Buffer.from(data);
    const timestamp = Math.floor(Date.now() / 1000);

    const tsBytes = Buffer.alloc(8);
    tsBytes.writeBigUInt64LE(BigInt(timestamp));
    const toSign = Buffer.concat([buf, tsBytes]);
    const signingKey = Buffer.from(signingKeyHex, 'hex');
    const keyObj = crypto.createPrivateKey({
      key: Buffer.concat([
        Buffer.from('302e020100300506032b657004220420', 'hex'), // PKCS#8 header for Ed25519
        signingKey.slice(0, 32),
      ]),
      format: 'der',
      type: 'pkcs8',
    });
    const signature = crypto.sign(null, toSign, keyObj);

    const headers: Record<string, string> = {
      'Content-Type': contentType,
      'X-0x01-Agent-Id': agentIdHex,
      'X-0x01-Timestamp': String(timestamp),
      'X-0x01-Signature': signature.toString('hex'),
    };
    if (filename) headers['X-0x01-Filename'] = filename;

    const res = await fetch(`${this.baseUrl}/blobs`, {
      method: 'POST',
      headers,
      body: buf,
    });
    if (!res.ok) {
      const err = await res.text();
      throw new Error(`uploadBlob failed (${res.status}): ${err}`);
    }
    return res.json() as Promise<UploadBlobResult>;
  }

  /** Download a blob by its CID. Returns raw bytes and metadata. */
  async downloadBlob(cid: string): Promise<{ data: Buffer; meta: BlobMeta }> {
    const [dataRes, metaRes] = await Promise.all([
      fetch(`${this.baseUrl}/blobs/${cid}`),
      fetch(`${this.baseUrl}/blobs/${cid}/meta`),
    ]);
    if (!dataRes.ok) throw new Error(`downloadBlob failed: HTTP ${dataRes.status}`);
    const arrayBuf = await dataRes.arrayBuffer();
    const meta = metaRes.ok
      ? (await metaRes.json() as BlobMeta)
      : { cid, filename: '', content_type: 'application/octet-stream' };
    return { data: Buffer.from(arrayBuf), meta };
  }

  /** Fetch metadata for a blob without downloading the body. */
  async getBlobMeta(cid: string): Promise<BlobMeta> {
    const res = await fetch(`${this.baseUrl}/blobs/${cid}/meta`);
    if (!res.ok) throw new Error(`getBlobMeta failed: HTTP ${res.status}`);
    return res.json() as Promise<BlobMeta>;
  }
}
