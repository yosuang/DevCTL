// Opened from the receiver code fragment. A scanned or pasted dct1 ticket is previewed.
// The Confirm control sends confirm: true.
const VERSION = 1;
const SESSION_PREVIEW = "/v1/sessions/preview";
const TICKET_PREVIEW = "/v1/tickets/preview";
const TICKET_CHALLENGE = "/v1/tickets/challenge";
const TICKET_CONFIRM = "/v1/tickets/confirm";
const FRAGMENT_KEY = "sc";
const TICKET_PREFIX = "dct1.";
const CAPABILITY_BYTES = 32;
const PUBKEY_BYTES = 32;
const NONCE_BYTES = 32;
const CONFIRM_SCOPE = "devctl-pair/confirm/v1";
const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
function utf8(value) {
    const Encoder = globalThis.TextEncoder;
    if (!Encoder)
        throw new Error("encoder");
    return new Encoder().encode(value);
}
function concat(parts) {
    let length = 0;
    for (const part of parts)
        length += part.length;
    const out = new Uint8Array(length);
    let offset = 0;
    for (const part of parts) {
        out.set(part, offset);
        offset += part.length;
    }
    return out;
}
function encodeB64Url(bytes) {
    let out = "";
    for (let i = 0; i < bytes.length; i += 3) {
        const a = bytes[i] ?? 0;
        const b = i + 1 < bytes.length ? (bytes[i + 1] ?? 0) : 0;
        const c = i + 2 < bytes.length ? (bytes[i + 2] ?? 0) : 0;
        const triple = (a << 16) | (b << 8) | c;
        out += B64[(triple >> 18) & 63];
        out += B64[(triple >> 12) & 63];
        if (i + 1 < bytes.length)
            out += B64[(triple >> 6) & 63];
        if (i + 2 < bytes.length)
            out += B64[triple & 63];
    }
    return out;
}
function decodeB64Url(value) {
    if (value.length === 0 || value.length % 4 === 1)
        return null;
    const bytes = [];
    let buffer = 0;
    let bits = 0;
    for (const char of value) {
        const index = B64.indexOf(char);
        if (index < 0)
            return null;
        buffer = (buffer << 6) | index;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            bytes.push((buffer >> bits) & 0xff);
        }
    }
    return Uint8Array.from(bytes);
}
function encodeHex(bytes) {
    let out = "";
    for (const byte of bytes)
        out += byte.toString(16).padStart(2, "0");
    return out;
}
function subtle() {
    const cryptoHost = globalThis.crypto;
    if (!cryptoHost?.subtle)
        throw new Error("crypto");
    return cryptoHost.subtle;
}
async function sha256(data) {
    const copy = new Uint8Array(data);
    return new Uint8Array(await subtle().digest("SHA-256", copy));
}
async function confirmDigestBytes(input) {
    return sha256(concat([
        utf8(CONFIRM_SCOPE),
        new Uint8Array([0]),
        input.nonce,
        input.sessionHash,
        input.ticketHash,
        input.pubkey,
        new Uint8Array([1]),
    ]));
}
export function sessionCapabilityFromHash(hash) {
    const body = hash.startsWith("#") ? hash.slice(1) : hash;
    for (const part of body.split("&")) {
        const eq = part.indexOf("=");
        if (eq < 0 || part.slice(0, eq) !== FRAGMENT_KEY)
            continue;
        const value = part.slice(eq + 1);
        const raw = decodeB64Url(value);
        if (!raw || raw.length !== CAPABILITY_BYTES)
            return null;
        return value;
    }
    return null;
}
export function ticketFromText(text) {
    const trimmed = text.trim();
    const at = trimmed.indexOf(TICKET_PREFIX);
    if (at < 0)
        return null;
    const token = trimmed.slice(at + TICKET_PREFIX.length).split(/[^A-Za-z0-9_-]/)[0] ?? "";
    if (!token)
        return null;
    const raw = decodeB64Url(token);
    if (!raw || raw.length !== CAPABILITY_BYTES)
        return null;
    return token;
}
export async function previewTicketText(post, text) {
    const ticket = ticketFromText(text);
    if (!ticket)
        return null;
    return post(TICKET_PREVIEW, { v: VERSION, ticket });
}
export async function confirmTicket(post, input) {
    const ticketBytes = decodeB64Url(input.ticket);
    const sessionBytes = decodeB64Url(input.sessionCapability);
    const pubkey = decodeB64Url(input.pubkey);
    if (!ticketBytes || ticketBytes.length !== CAPABILITY_BYTES)
        return { v: VERSION, error: "bad_request" };
    if (!sessionBytes || sessionBytes.length !== CAPABILITY_BYTES)
        return { v: VERSION, error: "bad_request" };
    if (!pubkey || pubkey.length !== PUBKEY_BYTES)
        return { v: VERSION, error: "bad_request" };
    const ticketHash = await sha256(ticketBytes);
    const sessionHash = await sha256(sessionBytes);
    const challenge = await post(TICKET_CHALLENGE, {
        v: VERSION,
        ticket_hash: encodeHex(ticketHash),
        purpose: "confirm",
    });
    const nonceText = challenge.nonce;
    if (typeof nonceText !== "string")
        return challenge;
    const nonce = decodeB64Url(nonceText);
    if (!nonce || nonce.length !== NONCE_BYTES)
        return challenge;
    const digest = encodeB64Url(await confirmDigestBytes({ nonce, sessionHash, ticketHash, pubkey }));
    return post(TICKET_CONFIRM, {
        v: VERSION,
        ticket: input.ticket,
        session_capability: input.sessionCapability,
        confirm: true,
        nonce: nonceText,
        digest,
    });
}
function codeDetector() {
    const Ctor = globalThis
        .BarcodeDetector;
    if (typeof Ctor !== "function")
        return null;
    try {
        return new Ctor({ formats: ["qr_code"] });
    }
    catch {
        return null;
    }
}
function qrFn() {
    const value = globalThis.jsQR;
    return typeof value === "function" ? value : null;
}
function makeCanvas() {
    const doc = globalThis.document;
    const node = doc?.createElement?.("canvas");
    if (!node || typeof node !== "object")
        return null;
    const box = node;
    if (typeof box.getContext !== "function")
        return null;
    return box;
}
async function watchCamera(video, onText) {
    const detector = codeDetector();
    const decode = qrFn();
    if (!detector && !decode)
        return;
    const media = globalThis.navigator?.mediaDevices;
    if (!media?.getUserMedia)
        return;
    try {
        video.srcObject = await media.getUserMedia({ video: { facingMode: "environment" }, audio: false });
        await video.play();
    }
    catch {
        return;
    }
    const every = globalThis.setInterval;
    if (!every)
        return;
    let canvas = null;
    let painter = null;
    let busy = false;
    every(() => {
        if (busy || video.readyState < 2)
            return;
        const width = video.videoWidth;
        const height = video.videoHeight;
        if (!width || !height)
            return;
        if (detector) {
            busy = true;
            void detector.detect(video).then((hits) => {
                busy = false;
                const text = hits[0]?.rawValue;
                if (text)
                    onText(text);
            }, () => {
                busy = false;
            });
            return;
        }
        if (!decode)
            return;
        if (!canvas || !painter) {
            canvas = makeCanvas();
            painter = canvas?.getContext("2d") ?? null;
        }
        if (!canvas || !painter)
            return;
        canvas.width = width;
        canvas.height = height;
        painter.drawImage(video, 0, 0);
        const frame = painter.getImageData(0, 0, width, height);
        const hit = decode(frame.data, frame.width, frame.height);
        if (hit?.data)
            onText(hit.data);
    }, 300);
}
export async function mount(input) {
    input.confirm.disabled = true;
    const capability = sessionCapabilityFromHash(input.hash);
    if (!capability) {
        input.status.textContent = "Open this page from the receiver code.";
        return;
    }
    const session = await input.post(SESSION_PREVIEW, { v: VERSION, session_capability: capability });
    const pubkey = typeof session.pubkey === "string" ? session.pubkey : "";
    if (typeof session.fingerprint !== "string" || !pubkey) {
        input.status.textContent = typeof session.error === "string" ? session.error : "session_not_found";
        return;
    }
    input.fingerprint.textContent = session.fingerprint;
    input.status.textContent = "Scan or paste the ticket.";
    let shown = null;
    let inflight = null;
    let generation = 0;
    const settle = (done) => {
        input.onSettle?.(done);
    };
    const apply = async (text) => {
        const ticket = ticketFromText(text);
        if (!ticket) {
            if (text.trim() === "") {
                shown = null;
                input.confirm.disabled = true;
            }
            return;
        }
        if (ticket === shown || ticket === inflight)
            return;
        inflight = ticket;
        const generationNow = ++generation;
        const preview = await previewTicketText(input.post, text);
        if (generationNow !== generation)
            return;
        inflight = null;
        if (!preview || typeof preview.error === "string" || typeof preview.state !== "string") {
            shown = null;
            input.confirm.disabled = true;
            input.status.textContent = typeof preview?.error === "string" ? preview.error : "bad_request";
            return;
        }
        shown = ticket;
        input.confirm.disabled = false;
        input.status.textContent =
            preview.state === "open" ? "Ticket is open. Press Confirm to bind." : preview.state;
    };
    const runConfirm = async () => {
        if (!shown)
            return;
        const result = await confirmTicket(input.post, {
            ticket: shown,
            sessionCapability: capability,
            pubkey,
        });
        const printed = typeof result.fingerprint === "string" ? result.fingerprint : "";
        if (printed && printed !== input.fingerprint.textContent) {
            input.status.textContent = "Fingerprint differs.";
            return;
        }
        if (typeof result.error === "string") {
            input.status.textContent = result.error;
            return;
        }
        if (typeof result.state === "string")
            input.status.textContent = result.state;
    };
    input.ticket.addEventListener("input", () => {
        settle(apply(input.ticket.value));
    });
    input.confirm.addEventListener("click", () => {
        if (input.confirm.disabled || !shown)
            return;
        settle(runConfirm());
    });
    const deliver = (text) => {
        settle(apply(text));
    };
    if (input.watch)
        input.watch(deliver);
    else if (input.camera)
        void watchCamera(input.camera, deliver);
}
function asText(node) {
    if (!node || typeof node !== "object" || !("textContent" in node))
        return null;
    return node;
}
function asField(node) {
    if (!node || typeof node !== "object")
        return null;
    const field = node;
    if (typeof field.value !== "string" || typeof field.addEventListener !== "function")
        return null;
    return field;
}
function asButton(node) {
    if (!node || typeof node !== "object")
        return null;
    const button = node;
    if (typeof button.disabled !== "boolean" || typeof button.addEventListener !== "function")
        return null;
    return button;
}
function asVideo(node) {
    if (!node || typeof node !== "object")
        return null;
    const video = node;
    if (typeof video.play !== "function")
        return null;
    if (typeof video.readyState !== "number")
        return null;
    if (typeof video.videoWidth !== "number" || typeof video.videoHeight !== "number")
        return null;
    return video;
}
async function postJson(path, body) {
    const fetchFn = globalThis.fetch;
    if (!fetchFn)
        return {};
    try {
        const response = await fetchFn(path, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify(body),
        });
        const parsed = await response.json();
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
            return {};
        return parsed;
    }
    catch {
        return {};
    }
}
function boot() {
    const host = globalThis;
    const doc = host.document;
    if (!doc || typeof doc.getElementById !== "function")
        return;
    const fingerprint = asText(doc.getElementById("fingerprint"));
    const status = asText(doc.getElementById("status"));
    const ticket = asField(doc.getElementById("ticket"));
    const confirm = asButton(doc.getElementById("confirm"));
    if (!fingerprint || !status || !ticket || !confirm)
        return;
    void mount({
        hash: host.location?.hash ?? "",
        fingerprint,
        status,
        ticket,
        confirm,
        camera: asVideo(doc.getElementById("camera")),
        post: postJson,
    });
}
boot();
