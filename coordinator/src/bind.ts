import { decodeB64Url, encodeHex, sha256 } from "./bytes";
import { errorStatus, protocol, type PageResult } from "./protocol";
import type { TicketResult } from "./ticket";

export interface ConfirmRequest {
  ticket: string;
  sessionCapability: string;
  confirm: boolean;
  nonce: string;
  digest: string;
}

function page(result: TicketResult): PageResult {
  const body: PageResult = { v: protocol.version };
  if (result.state) body.state = result.state;
  if (result.fingerprint) body.fingerprint = result.fingerprint;
  if (result.expires_at !== undefined) body.expires_at = result.expires_at;
  if (result.error) body.error = result.error;
  return body;
}

async function named(secret: string): Promise<{ name: string } | null> {
  const raw = decodeB64Url(secret);
  if (!raw || raw.length !== protocol.capability_bytes) return null;
  return { name: encodeHex(await sha256(raw)) };
}

export async function finishConfirm(env: Env, input: ConfirmRequest): Promise<PageResult> {
  const ticketName = await named(input.ticket);
  if (!ticketName) return { v: protocol.version, error: "bad_request" };
  const ticket = env.TICKET.getByName(ticketName.name);
  if (input.confirm !== true) {
    return page(await ticket.confirm({ confirm: false }));
  }
  const sessionName = await named(input.sessionCapability);
  if (!sessionName) return { v: protocol.version, error: "bad_request" };
  const session = env.SESSION.getByName(sessionName.name);
  const pub = await session.previewPubkey({ capability: input.sessionCapability });
  if ("error" in pub) return { v: protocol.version, error: pub.error };
  const result = await ticket.confirm({
    confirm: true,
    pubkey: pub.pubkey,
    sessionHash: sessionName.name,
    nonce: input.nonce,
    digest: input.digest,
  });
  if (result.state === "bound" && result.hint && !result.error) {
    let notified = false;
    try {
      notified = await session.notify(result.hint);
    } catch {
      notified = false;
    }
    if (!notified) {
      return {
        v: protocol.version,
        state: "bound",
        error: "bound_notify_pending",
        expires_at: result.expires_at,
        fingerprint: result.fingerprint,
      };
    }
  }
  return page(result);
}

export function pageStatus(result: PageResult): number {
  if (result.error) return errorStatus(result.error);
  return protocol.http.success;
}
