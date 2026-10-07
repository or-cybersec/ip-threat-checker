import { isIP } from "node:net";

export type HttpResult = {
  ok: boolean;
  status: number;
  json: unknown;
  error?: string;
};

const MAX_BODY = 1_000_000;
const MAX_HOPS = 3;

const FEED_HOSTS = [
  "ipinfo.io",
  "virustotal.com",
  "abuseipdb.com",
  "greynoise.io",
  "shodan.io",
  "rdap.org",
  "arin.net",
  "ripe.net",
  "apnic.net",
  "lacnic.net",
  "afrinic.net",
  "alienvault.com",
  "microsoftonline.com",
  "microsoft.com",
];

/** Redirects may leave the original host (RDAP bootstrap) but only onto a known feed domain. */
export function feedHostAllowed(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  if (!host || host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local")) return false;
  if (isIP(host)) return false;
  return FEED_HOSTS.some((suffix) => host === suffix || host.endsWith(`.${suffix}`));
}

async function readLimited(response: Response, max: number): Promise<string | null> {
  const declared = Number(response.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > max) {
    await response.body?.cancel();
    return null;
  }
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let received = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    received += value.byteLength;
    if (received > max) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const merged = new Uint8Array(received);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(merged);
}

function dropCredentialHeaders(headers: Headers) {
  for (const name of ["authorization", "x-apikey", "key", "x-otx-api-key"]) headers.delete(name);
}

export async function fetchJson(
  url: string,
  init: RequestInit | undefined,
  signal: AbortSignal | undefined,
  timeoutMs = 12000,
): Promise<HttpResult> {
  try {
    const timeout = AbortSignal.timeout(timeoutMs);
    const combined = signal ? AbortSignal.any([timeout, signal]) : timeout;
    let current = new URL(url);
    if (current.protocol !== "https:" || !feedHostAllowed(current.hostname)) {
      return { ok: false, status: 0, json: null, error: "Feed host is not allowed." };
    }
    let method = init?.method ?? "GET";
    let body = init?.body;
    const headers = new Headers(init?.headers);
    if (!headers.has("accept")) headers.set("accept", "application/json");
    if (!headers.has("user-agent")) headers.set("user-agent", "IPThreatChecker/1.0");

    for (let hop = 0; hop <= MAX_HOPS; hop += 1) {
      const response = await fetch(current, { method, headers, body, signal: combined, redirect: "manual" });
      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get("location");
        await response.body?.cancel();
        if (!location || hop === MAX_HOPS) {
          return { ok: false, status: response.status, json: null, error: "Upstream redirect was rejected." };
        }
        const next = new URL(location, current);
        if (next.protocol !== "https:" || !feedHostAllowed(next.hostname)) {
          return { ok: false, status: response.status, json: null, error: "Upstream redirect was rejected." };
        }
        if (next.hostname !== current.hostname) dropCredentialHeaders(headers);
        if ((response.status === 301 || response.status === 302 || response.status === 303) && method !== "GET" && method !== "HEAD") {
          method = "GET";
          body = undefined;
          headers.delete("content-type");
        }
        current = next;
        continue;
      }
      const text = await readLimited(response, MAX_BODY);
      if (text === null) {
        return { ok: false, status: response.status, json: null, error: "Upstream response was too large." };
      }
      let json: unknown = null;
      if (text) {
        try {
          json = JSON.parse(text) as unknown;
        } catch {
          json = { raw: text.slice(0, 280) };
        }
      }
      return { ok: response.ok, status: response.status, json };
    }
    return { ok: false, status: 0, json: null, error: "Upstream redirect was rejected." };
  } catch (error) {
    const message = error instanceof Error ? error.message : "Request failed";
    if (signal?.aborted) return { ok: false, status: 0, json: null, error: "Cancelled" };
    const timedOut = /abort|timeout/i.test(message);
    return { ok: false, status: 0, json: null, error: timedOut ? "Timed out" : message };
  }
}
