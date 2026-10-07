import { getSql } from "@/lib/db";

import { assess } from "./assess";
import { clientAddress, extractAddress } from "./address";
import { compareLookups } from "./delta";
import { resolveKeys } from "./keys";
import { mergePatch } from "./merge";
import {
  queryAbuseIpdb,
  queryGreyNoise,
  queryIpinfo,
  queryMdti,
  queryOtx,
  queryShodan,
  querySpamhaus,
  queryVirusTotal,
  queryWhois,
  type ProviderOutcome,
} from "./providers.server";
import { asRecord } from "./read";
import type { Dossier, FeedId, FeedKeys, IntelPatch, SourceMeta, StreamEvent, Verdict } from "./types";
import { FEEDS } from "./types";

type CacheEntry = { exp: number; storedAt: number; outcome: ProviderOutcome };

const cache = new Map<string, CacheEntry>();
const hits = new Map<string, number[]>();
let inflight = 0;

const LABEL = new Map(FEEDS.map((feed) => [feed.id, feed.label]));

function credTag(secret?: string): string {
  if (!secret) return "0";
  let hash = 2166136261;
  for (let i = 0; i < secret.length; i += 1) {
    hash ^= secret.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0).toString(36);
}

function cacheGet(key: string): CacheEntry | null {
  const entry = cache.get(key);
  if (!entry) return null;
  if (entry.exp < Date.now()) {
    cache.delete(key);
    return null;
  }
  return entry;
}

function cacheSet(key: string, outcome: ProviderOutcome, ttl: number) {
  if (cache.size > 240) {
    const oldest = cache.keys().next().value;
    if (oldest) cache.delete(oldest);
  }
  cache.set(key, { exp: Date.now() + ttl, storedAt: Date.now(), outcome });
}

function allow(client: string): boolean {
  const now = Date.now();
  if (!hits.has(client) && hits.size >= 2000) {
    const oldest = hits.keys().next().value;
    if (oldest) hits.delete(oldest);
  }
  const recent = (hits.get(client) ?? []).filter((stamp) => now - stamp < 60_000);
  if (recent.length >= 15) {
    hits.set(client, recent);
    return false;
  }
  recent.push(now);
  hits.set(client, recent);
  return true;
}

function clientKey(request: Request): string {
  return clientAddress(request.headers);
}

function cleanKeys(value: unknown): FeedKeys {
  const rec = asRecord(value) ?? {};
  const pick = (key: keyof FeedKeys) => {
    const raw = rec[key];
    if (typeof raw !== "string") return undefined;
    const trimmed = raw.trim();
    if (!trimmed || trimmed.length > 400) return undefined;
    return trimmed;
  };
  return {
    virustotal: pick("virustotal"),
    abuseipdb: pick("abuseipdb"),
    greynoise: pick("greynoise"),
    shodan: pick("shodan"),
    ipinfo: pick("ipinfo"),
    otx: pick("otx"),
    mdtiTenant: pick("mdtiTenant"),
    mdtiClientId: pick("mdtiClientId"),
    mdtiClientSecret: pick("mdtiClientSecret"),
  };
}

function fingerprint(keys: FeedKeys): string {
  return [
    credTag(keys.virustotal),
    credTag(keys.abuseipdb),
    credTag(keys.greynoise),
    credTag(keys.shodan),
    credTag(keys.ipinfo),
    credTag(keys.otx),
    credTag(keys.mdtiTenant),
    credTag(keys.mdtiClientId),
    credTag(keys.mdtiClientSecret),
  ].join(".");
}

async function runProvider(
  id: FeedId,
  ip: string,
  version: 4 | 6,
  keys: FeedKeys,
  signal: AbortSignal,
  tag: string,
): Promise<{ outcome: ProviderOutcome; ms: number; cached: boolean; cachedAt?: string }> {
  const secret = secretFor(id, keys);
  const key = `${id}:${ip}:${tag}:${credTag(secret)}`;
  const hit = cacheGet(key);
  if (hit) {
    return {
      outcome: hit.outcome,
      ms: 0,
      cached: true,
      cachedAt: new Date(hit.storedAt).toISOString(),
    };
  }
  const started = Date.now();
  let outcome: ProviderOutcome;
  try {
    if (id === "ipinfo") outcome = await queryIpinfo(ip, keys, signal);
    else if (id === "virustotal") outcome = await queryVirusTotal(ip, keys, signal);
    else if (id === "abuseipdb") outcome = await queryAbuseIpdb(ip, keys, signal);
    else if (id === "greynoise") outcome = await queryGreyNoise(ip, version, keys, signal);
    else if (id === "shodan") outcome = await queryShodan(ip, keys, signal);
    else if (id === "whois") outcome = await queryWhois(ip, signal);
    else if (id === "otx") outcome = await queryOtx(ip, version, keys, signal);
    else if (id === "mdti") outcome = await queryMdti(ip, keys, signal);
    else outcome = await querySpamhaus(ip, version);
  } catch (error) {
    outcome = {
      status: "error",
      detail: error instanceof Error ? error.message.slice(0, 180) : "Feed failed",
      part: {},
    };
  }
  if (!signal.aborted && (outcome.status === "ok" || outcome.status === "empty")) {
    cacheSet(key, outcome, 10 * 60_000);
  } else if (outcome.status === "rate_limited") {
    cacheSet(key, outcome, 60_000);
  }
  return { outcome, ms: Date.now() - started, cached: false };
}

function toIso(value: unknown): string {
  if (value instanceof Date && !Number.isNaN(value.getTime())) return value.toISOString();
  if (typeof value === "string") {
    const date = new Date(value);
    if (!Number.isNaN(date.getTime())) return date.toISOString();
  }
  return new Date().toISOString();
}

async function previousLookup(ip: string): Promise<Dossier | null> {
  try {
    const sql = await getSql();
    const rows = await sql.query<{ result: unknown }>(
      `select result from lookups where ip = $1 order by id desc limit 1`,
      [ip],
    );
    const row = rows[0];
    if (!row) return null;
    return parseJson<Dossier>(row.result);
  } catch (error) {
    console.error("[checker] previous lookup failed", error instanceof Error ? error.message : error);
    return null;
  }
}

async function persist(dossier: Dossier): Promise<{ id?: number; logStatus: Dossier["logStatus"] }> {
  try {
    const sql = await getSql();
    const stored = { ...dossier, logStatus: "saved" as const };
    const rows = await sql.query<{ id: number }>(
      `insert into lookups (ip, verdict, score, summary, sources, result)
       values ($1, $2, $3, $4, $5::jsonb, $6::jsonb)
       returning id`,
      [
        dossier.ip,
        dossier.verdict,
        dossier.score,
        dossier.summary,
        JSON.stringify(dossier.sources),
        JSON.stringify(stored),
      ],
    );
    const id = rows[0]?.id;
    return { id: typeof id === "number" ? id : Number(id), logStatus: "saved" };
  } catch (error) {
    console.error("[checker] lookup log failed", error instanceof Error ? error.message : error);
    return { logStatus: "unavailable" };
  }
}

function buildDossier(
  ip: string,
  version: 4 | 6,
  cgnat: boolean,
  queriedAt: string,
  patch: IntelPatch,
  sources: SourceMeta[],
): Dossier {
  const assessment = assess({
    ip,
    version,
    cgnat,
    geo: patch.geo,
    asn: patch.asn,
    reputation: patch.reputation ?? null,
    abuse: patch.abuse ?? null,
    greynoise: patch.greynoise ?? null,
    shodan: patch.shodan ?? null,
    whois: patch.whois ?? null,
    otx: patch.otx ?? null,
    mdti: patch.mdti ?? null,
    spamhaus: patch.blocklist?.spamhaus ?? null,
    sources,
  });
  const cached =
    sources.some((source) => source.cached) &&
    sources.every((source) => source.cached || source.status === "no_key" || source.status === "unsupported");
  return {
    ip,
    version,
    queriedAt,
    cached,
    cgnat,
    geo: patch.geo ?? {},
    asn: patch.asn ?? {},
    reputation: patch.reputation ?? null,
    abuse: patch.abuse ?? null,
    greynoise: patch.greynoise ?? null,
    shodan: patch.shodan ?? null,
    whois: patch.whois ?? null,
    otx: patch.otx ?? null,
    mdti: patch.mdti ?? null,
    blocklist: patch.blocklist ?? null,
    passiveDns: assessment.passiveDns,
    timeline: assessment.timeline,
    tags: assessment.tags,
    findings: assessment.findings,
    summary: assessment.summary,
    recommendation: assessment.recommendation,
    actions: assessment.actions,
    changes: null,
    verdict: assessment.verdict,
    score: assessment.score,
    sources,
    logStatus: "unavailable",
  };
}

export async function handleLookup(request: Request): Promise<Response> {
  let body: unknown;
  try {
    const text = await request.text();
    if (text.length > 20_000) {
      return Response.json({ message: "Request is too large." }, { status: 413 });
    }
    body = text ? (JSON.parse(text) as unknown) : {};
  } catch {
    return Response.json({ message: "Request body must be JSON." }, { status: 400 });
  }
  const rec = asRecord(body);
  const checked = extractAddress(typeof rec?.ip === "string" ? rec.ip : "");
  if (!checked.ok) return Response.json({ message: checked.message }, { status: 400 });
  if (!allow(clientKey(request))) {
    return Response.json(
      { message: "Rate limit reached. Wait a minute before the next lookup." },
      { status: 429 },
    );
  }
  if (inflight >= 4) {
    return Response.json(
      { message: "Too many lookups are running. Try again in a few seconds." },
      { status: 429 },
    );
  }

  const keys = resolveKeys(cleanKeys(rec?.keys), rec?.useWorkspaceKeys === true);
  const tag = fingerprint(keys);
  const encoder = new TextEncoder();
  const abort = new AbortController();
  let released = false;
  const release = () => {
    if (released) return;
    released = true;
    inflight = Math.max(0, inflight - 1);
  };
  inflight += 1;
  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      let closed = false;
      const send = (event: StreamEvent) => {
        if (closed) return;
        try {
          controller.enqueue(encoder.encode(`${JSON.stringify(event)}\n`));
        } catch {
          closed = true;
          abort.abort();
        }
      };
      try {
        send({ type: "meta", ip: checked.ip, version: checked.version, cgnat: checked.cgnat, fromLine: checked.fromLine });
        const queriedAt = new Date().toISOString();
        let patch: IntelPatch = {};
        const sources: SourceMeta[] = [];
        const jobs: FeedId[] = [
          "ipinfo",
          "virustotal",
          "abuseipdb",
          "greynoise",
          "shodan",
          "whois",
          "otx",
          "mdti",
          "spamhaus",
        ];
        await Promise.all(
          jobs.map(async (id) => {
            const { outcome, ms, cached, cachedAt } = await runProvider(
              id,
              checked.ip,
              checked.version,
              keys,
              abort.signal,
              tag,
            );
            const meta: SourceMeta = {
              id,
              label: LABEL.get(id) ?? id,
              status: outcome.status,
              detail: outcome.detail,
              ms,
              cached,
              cachedAt,
            };
            sources.push(meta);
            patch = mergePatch(patch, outcome.part);
            send({ type: "fragment", source: meta, patch: outcome.part });
          }),
        );
        sources.sort((a, b) => jobs.indexOf(a.id) - jobs.indexOf(b.id));
        let dossier = buildDossier(checked.ip, checked.version, checked.cgnat, queriedAt, patch, sources);
        const previous = await previousLookup(checked.ip);
        dossier = {
          ...dossier,
          changes: previous ? compareLookups(previous, dossier) : null,
          previousAt: previous?.queriedAt,
        };
        const saved = await persist(dossier);
        dossier = { ...dossier, historyId: saved.id, logStatus: saved.logStatus };
        send({ type: "complete", dossier });
      } catch (error) {
        send({
          type: "fatal",
          message: error instanceof Error ? error.message : "Lookup failed.",
        });
      } finally {
        release();
        closed = true;
        try {
          controller.close();
        } catch {
          /* already closed */
        }
      }
    },
    cancel() {
      abort.abort();
    },
  });

  return new Response(stream, {
    headers: {
      "content-type": "application/x-ndjson; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
    },
  });
}

function secretFor(id: FeedId, keys: FeedKeys): string {
  if (id === "virustotal") return keys.virustotal ?? "";
  if (id === "abuseipdb") return keys.abuseipdb ?? "";
  if (id === "greynoise") return keys.greynoise ?? "";
  if (id === "shodan") return keys.shodan ?? "";
  if (id === "ipinfo") return keys.ipinfo ?? "";
  if (id === "otx") return keys.otx ?? "";
  if (id === "mdti") return `${keys.mdtiTenant ?? ""}:${keys.mdtiClientId ?? ""}:${keys.mdtiClientSecret ?? ""}`;
  return "";
}

export function envFlags() {
  const env = process.env;
  return {
    virustotal: Boolean(env.VIRUSTOTAL_API_KEY?.trim()),
    abuseipdb: Boolean(env.ABUSEIPDB_API_KEY?.trim()),
    greynoise: Boolean(env.GREYNOISE_API_KEY?.trim()),
    shodan: Boolean(env.SHODAN_API_KEY?.trim()),
    ipinfo: Boolean(env.IPINFO_TOKEN?.trim()),
    otx: Boolean(env.OTX_API_KEY?.trim()),
    mdti: Boolean(env.MDTI_TENANT_ID?.trim() && env.MDTI_CLIENT_ID?.trim() && env.MDTI_CLIENT_SECRET?.trim()),
  };
}

function parseJson<T>(value: unknown): T {
  if (typeof value === "string") return JSON.parse(value) as T;
  return value as T;
}

export async function clearHistory(): Promise<void> {
  const sql = await getSql();
  await sql.query(`delete from lookups`);
}

const VERDICTS = ["critical", "suspicious", "benign", "unknown"] as const;

export function isVerdict(value: string | null): value is Verdict {
  return VERDICTS.some((verdict) => verdict === value);
}

export async function clearVerdictHistory(verdict: Verdict): Promise<number> {
  const sql = await getSql();
  const rows = await sql.query<{ id: number }>(`delete from lookups where verdict = $1 returning id`, [verdict]);
  return rows.length;
}

export async function deleteHistory(id: number): Promise<boolean> {
  const sql = await getSql();
  const rows = await sql.query<{ id: number }>(`delete from lookups where id = $1 returning id`, [id]);
  return rows.length > 0;
}

export async function listHistory() {
  const sql = await getSql();
  const rows = await sql.query<{
    id: number;
    ip: string;
    verdict: string;
    score: number;
    summary: string;
    created_at: unknown;
  }>(
    `select id, ip, verdict, score, summary, created_at
     from lookups
     order by id desc
     limit 30`,
  );
  return rows.map((row) => ({
    id: Number(row.id),
    ip: row.ip,
    verdict: row.verdict as Verdict,
    score: Number(row.score),
    summary: row.summary,
    createdAt: toIso(row.created_at),
  }));
}

export async function readHistory(id: number): Promise<Dossier | null> {
  const sql = await getSql();
  const rows = await sql.query<{ id: number; result: unknown; created_at: unknown }>(
    `select id, result, created_at from lookups where id = $1`,
    [id],
  );
  const row = rows[0];
  if (!row) return null;
  const dossier = parseJson<Dossier>(row.result);
  return { ...dossier, historyId: Number(row.id), queriedAt: dossier.queriedAt || toIso(row.created_at), logStatus: "saved" };
}

export function historyId(value: string | null): number | null {
  if (!value || !/^\d{1,10}$/.test(value)) return null;
  const id = Number(value);
  return Number.isInteger(id) && id > 0 ? id : null;
}
