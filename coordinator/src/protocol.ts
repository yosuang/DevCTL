import vocabulary from "../../internal/pair/protocol/v1.json";

export const protocol = vocabulary;

export type TicketState = (typeof protocol.states)[number];
export type ServerError = (typeof protocol.errors.server)[number];
export type SignatureName = keyof typeof protocol.signatures;

type Assert<T extends true> = T;
export type TerminalStatesFit = Assert<
  (typeof protocol.terminal_states)[number] extends TicketState ? true : false
>;
export type HintStatesFit = Assert<(typeof protocol.hint_states)[number] extends TicketState ? true : false>;

const statusCodes: Record<ServerError, number> = protocol.error_status;

export function errorStatus(error: ServerError): number {
  return statusCodes[error];
}

export function isServerError(value: string): value is ServerError {
  return (protocol.errors.server as readonly string[]).includes(value);
}

export function isTerminal(state: string): boolean {
  return (protocol.terminal_states as readonly string[]).includes(state);
}

export function isHintState(state: string): boolean {
  return (protocol.hint_states as readonly string[]).includes(state);
}

export interface Hint {
  v: number;
  state: (typeof protocol.hint_states)[number];
  ticket_hash: string;
  seed_nonce: string;
  expires_at: number;
}

export interface PageResult {
  v: number;
  state?: TicketState;
  fingerprint?: string;
  expires_at?: number;
  error?: ServerError;
}
