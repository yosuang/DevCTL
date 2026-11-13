import { finishConfirm, pageStatus } from "./bind";
import { decodeB64Url, encodeHex, originFromUrl, sha256 } from "./bytes";
import { admit, sourceKey } from "./gate";
import {
  boolField,
  errorResponse,
  intField,
  jsonResponse,
  objectShape,
  oneOf,
  readBody,
  textField,
} from "./http";
import { logResult, routeName } from "./log";
import { errorStatus, protocol, type PageResult, type ServerError } from "./protocol";
import type { TicketResult } from "./ticket";

export { CreateGate } from "./gate";
export { SessionDO } from "./session";
export { TicketDO } from "./ticket";

interface Located {
  stubName: string;
}

async function locate(secret: string): Promise<Located | null> {
  const raw = decodeB64Url(secret);
  if (!raw || raw.length !== protocol.capability_bytes) return null;
  return { stubName: encodeHex(await sha256(raw)) };
}

function pageBody(result: PageResult): Response {
  return jsonResponse(result, pageStatus(result));
}

function ticketBody(result: TicketResult, includeEnvelope: boolean): Response {
  const body: Record<string, unknown> = { v: protocol.version };
  if (result.state) body.state = result.state;
  if (result.expires_at !== undefined) body.expires_at = result.expires_at;
  if (result.fingerprint) body.fingerprint = result.fingerprint;
  if (result.nonce) body.nonce = result.nonce;
  if (result.error) body.error = result.error;
  else if (includeEnvelope && result.envelope !== undefined) body.envelope = result.envelope;
  const status = result.error ? errorStatus(result.error) : protocol.http.success;
  return jsonResponse(body, status);
}

async function createTicket(request: Request, env: Env, record: Record<string, unknown>): Promise<Response> {
  const ticket = textField(record, "ticket");
  const issuer = textField(record, "issuer_capability");
  const envelope = textField(record, "envelope");
  if (!ticket || !issuer || !envelope) return errorResponse("bad_request");
  const located = await locate(ticket);
  if (!located) return errorResponse("bad_request");
  const stub = env.TICKET.getByName(located.stubName);
  let result = await stub.create({ ticket, issuer_capability: issuer, envelope });
  if (result.error === "unauthorized") {
    const granted = await admit(env, sourceKey(request));
    if ("error" in granted) return errorResponse(granted.error);
    result = await stub.create({
      ticket,
      issuer_capability: issuer,
      envelope,
      grant_id: granted.id,
      grant_source: granted.source_name,
    });
  }
  return ticketBody(result, false);
}

async function handlePost(request: Request, env: Env, url: URL): Promise<Response> {
  const origin = originFromUrl(url);
  const body = await readBody(request);
  if ("error" in body) return errorResponse(body.error);
  let parsed: unknown;
  try {
    parsed = JSON.parse(body.text);
  } catch {
    return errorResponse("bad_request");
  }
  const path = url.pathname;
  if (path === protocol.routes.tickets) {
    const shaped = objectShape(parsed, protocol.bodies.create);
    if (!shaped.ok) return errorResponse(shaped.error);
    return createTicket(request, env, shaped.value);
  }
  if (path === protocol.routes.ticket_preview) {
    const shaped = objectShape(parsed, protocol.bodies.ticket_preview);
    if (!shaped.ok) return errorResponse(shaped.error);
    const ticket = textField(shaped.value, "ticket");
    const located = ticket ? await locate(ticket) : null;
    if (!located) return errorResponse("bad_request");
    return ticketBody(await env.TICKET.getByName(located.stubName).preview(), false);
  }
  if (path === protocol.routes.ticket_challenge) {
    const shaped = oneOf(parsed, [protocol.bodies.ticket_challenge, protocol.bodies.ticket_challenge_redeem]);
    if (!shaped.ok) return errorResponse(shaped.error);
    const ticket = textField(shaped.value, "ticket");
    const purpose = textField(shaped.value, "purpose");
    const located = ticket ? await locate(ticket) : null;
    if (!ticket || !purpose || !located) return errorResponse("bad_request");
    return ticketBody(
      await env.TICKET.getByName(located.stubName).challenge({
        purpose,
        pubkey: textField(shaped.value, "pubkey") ?? undefined,
        signature: textField(shaped.value, "signature") ?? undefined,
        origin,
      }),
      false,
    );
  }
  if (path === protocol.routes.ticket_confirm) {
    const shaped = objectShape(parsed, protocol.bodies.confirm);
    if (!shaped.ok) return errorResponse(shaped.error);
    const ticket = textField(shaped.value, "ticket");
    const sessionCapability = textField(shaped.value, "session_capability");
    const confirm = boolField(shaped.value, "confirm");
    const nonce = textField(shaped.value, "nonce");
    const digest = textField(shaped.value, "digest");
    if (!ticket || !sessionCapability || confirm === null || nonce === null || digest === null) {
      return errorResponse("bad_request");
    }
    return pageBody(await finishConfirm(env, { ticket, sessionCapability, confirm, nonce, digest }));
  }
  if (path === protocol.routes.ticket_status) {
    const shaped = objectShape(parsed, protocol.bodies.status);
    if (!shaped.ok) return errorResponse(shaped.error);
    const ticket = textField(shaped.value, "ticket");
    const issuer = textField(shaped.value, "issuer_capability");
    const located = ticket ? await locate(ticket) : null;
    if (!issuer || !located) return errorResponse("bad_request");
    return ticketBody(await env.TICKET.getByName(located.stubName).status({ issuer_capability: issuer }), false);
  }
  if (path === protocol.routes.ticket_cancel) {
    const shaped = objectShape(parsed, protocol.bodies.cancel);
    if (!shaped.ok) return errorResponse(shaped.error);
    const ticket = textField(shaped.value, "ticket");
    const issuer = textField(shaped.value, "issuer_capability");
    const nonce = textField(shaped.value, "nonce");
    const digest = textField(shaped.value, "digest");
    const located = ticket ? await locate(ticket) : null;
    if (!issuer || !nonce || !digest || !located) return errorResponse("bad_request");
    return ticketBody(
      await env.TICKET.getByName(located.stubName).cancel({
        issuer_capability: issuer,
        nonce,
        digest,
      }),
      false,
    );
  }
  if (path === protocol.routes.ticket_read || path === protocol.routes.ticket_ack) {
    const keys = path === protocol.routes.ticket_read ? protocol.bodies.read : protocol.bodies.ack;
    const shaped = objectShape(parsed, keys);
    if (!shaped.ok) return errorResponse(shaped.error);
    const ticket = textField(shaped.value, "ticket");
    const pubkey = textField(shaped.value, "pubkey");
    const nonce = textField(shaped.value, "nonce");
    const signature = textField(shaped.value, "signature");
    const counter = intField(shaped.value, "counter");
    const located = ticket ? await locate(ticket) : null;
    if (!pubkey || !nonce || !signature || counter === null || !located) return errorResponse("bad_request");
    const stub = env.TICKET.getByName(located.stubName);
    const input = { pubkey, nonce, counter, signature, origin };
    const result =
      path === protocol.routes.ticket_read ? await stub.read(input) : await stub.ack(input);
    return ticketBody(result, path === protocol.routes.ticket_read);
  }
  if (path === protocol.routes.session_challenge) {
    const shaped = objectShape(parsed, protocol.bodies.session_challenge);
    if (!shaped.ok) return errorResponse(shaped.error);
    const capability = textField(shaped.value, "session_capability");
    const purpose = textField(shaped.value, "purpose");
    const located = capability ? await locate(capability) : null;
    if (!purpose || !located) return errorResponse("bad_request");
    return ticketBody(
      await env.SESSION.getByName(located.stubName).challenge({ sessionHash: located.stubName, purpose }),
      false,
    );
  }
  if (path === protocol.routes.session_hello) {
    const shaped = objectShape(parsed, protocol.bodies.hello);
    if (!shaped.ok) return errorResponse(shaped.error);
    const capability = textField(shaped.value, "session_capability");
    const pubkey = textField(shaped.value, "pubkey");
    const nonce = textField(shaped.value, "nonce");
    const signature = textField(shaped.value, "signature");
    const located = capability ? await locate(capability) : null;
    if (!pubkey || !nonce || !signature || !located) return errorResponse("bad_request");
    const result = await env.SESSION.getByName(located.stubName).hello({
      sessionHash: located.stubName,
      pubkey,
      nonce,
      signature,
      origin,
    });
    const bodyOut: Record<string, unknown> = { v: protocol.version };
    if (result.fingerprint) bodyOut.fingerprint = result.fingerprint;
    if (result.error) bodyOut.error = result.error;
    return jsonResponse(bodyOut, result.error ? errorStatus(result.error) : protocol.http.success);
  }
  if (path === protocol.routes.session_preview) {
    const shaped = objectShape(parsed, protocol.bodies.session_preview);
    if (!shaped.ok) return errorResponse(shaped.error);
    const capability = textField(shaped.value, "session_capability");
    const located = capability ? await locate(capability) : null;
    if (!located) return errorResponse("bad_request");
    const result = await env.SESSION.getByName(located.stubName).preview({ sessionHash: located.stubName });
    if (result.error) return errorResponse(result.error);
    return jsonResponse(
      { v: protocol.version, fingerprint: result.fingerprint, pubkey: result.pubkey },
      protocol.http.success,
    );
  }
  if (path === protocol.routes.session_wait) {
    const shaped = objectShape(parsed, protocol.bodies.wait);
    if (!shaped.ok) return errorResponse(shaped.error);
    const capability = textField(shaped.value, "session_capability");
    const pubkey = textField(shaped.value, "pubkey");
    const nonce = textField(shaped.value, "nonce");
    const signature = textField(shaped.value, "signature");
    const counter = intField(shaped.value, "counter");
    const located = capability ? await locate(capability) : null;
    if (!pubkey || !nonce || !signature || counter === null || !located) return errorResponse("bad_request");
    const result = await env.SESSION.getByName(located.stubName).wait({
      sessionHash: located.stubName,
      pubkey,
      nonce,
      counter,
      signature,
      origin,
    });
    if (result.error) return errorResponse(result.error);
    return jsonResponse({ v: protocol.version, hint: result.hint ?? null }, protocol.http.success);
  }
  return errorResponse("bad_request", 404);
}

async function handleSocket(request: Request, env: Env): Promise<Response> {
  const hash = request.headers.get(protocol.session_header) ?? "";
  if (!/^[0-9a-f]{64}$/.test(hash)) return errorResponse("unauthorized");
  return env.SESSION.getByName(hash).fetch(request);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const upgrade = request.headers.get("Upgrade");
    if (
      request.method === "GET" &&
      url.pathname === protocol.routes.session_socket &&
      upgrade?.toLowerCase() === "websocket"
    ) {
      const response = await handleSocket(request, env);
      logResult(routeName(url.pathname), response.status);
      return response;
    }
    if (request.method === "GET" && url.pathname.startsWith("/v1/")) {
      const response = errorResponse("bad_request", protocol.http.method_not_allowed);
      logResult(routeName(url.pathname), response.status, "bad_request");
      return response;
    }
    if (request.method === "GET") {
      return env.ASSETS.fetch(request);
    }
    if (request.method !== "POST" || !url.pathname.startsWith("/v1/")) {
      const response = errorResponse("bad_request", protocol.http.method_not_allowed);
      logResult(routeName(url.pathname), response.status, "bad_request");
      return response;
    }
    try {
      const response = await handlePost(request, env, url);
      let error: ServerError | undefined;
      const cloned = response.clone();
      try {
        const payload = (await cloned.json()) as { error?: string };
        if (payload.error && (protocol.errors.server as readonly string[]).includes(payload.error)) {
          error = payload.error as ServerError;
        }
      } catch {
        error = undefined;
      }
      logResult(routeName(url.pathname), response.status, error);
      return response;
    } catch {
      logResult(routeName(url.pathname), protocol.error_status.bad_request, "bad_request");
      return errorResponse("bad_request");
    }
  },
};
