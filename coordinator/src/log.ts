import { isServerError, protocol, type ServerError } from "./protocol";

const routes = new Set<string>([...Object.keys(protocol.routes), "unknown"]);
const lines: string[] = [];

export interface LogFields {
  route?: string;
  error?: string;
  status?: number;
}

export function logEvent(event: "result", fields: LogFields): void {
  const safe: Record<string, string | number> = {};
  if (fields.route && routes.has(fields.route)) safe.route = fields.route;
  if (fields.error && isServerError(fields.error)) safe.error = fields.error;
  if (typeof fields.status === "number" && Number.isFinite(fields.status)) {
    safe.status = fields.status;
  }
  const line = JSON.stringify({ event, ...safe });
  lines.push(line);
  if (lines.length > 200) lines.shift();
  console.log(line);
}

export function recentLogs(): string[] {
  return [...lines];
}

export function clearLogs(): void {
  lines.length = 0;
}

export function routeName(pathname: string): string {
  for (const [name, path] of Object.entries(protocol.routes)) {
    if (path === pathname) return name;
  }
  return "unknown";
}

export function logResult(route: string, status: number, error?: ServerError): void {
  logEvent("result", { route, status, error });
}
