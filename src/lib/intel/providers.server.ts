import { promises as dns } from "node:dns";

import type { FeedId, FeedKeys, IntelPatch, SourceStatus } from "./types";
import { asBool, asNumber, asRecord, asString, tagList, unique, unixToIso } from "./read";
import { fetchJson } from "./http.server";

export type ProviderOutcome = {
  status: SourceStatus;
  detail?: string;
  part: IntelPatch;
};

const ABUSE_CATEGORIES: Record<number, string> = {
  1: "DNS Compromise",
  2: "DNS Poisoning",
  3: "Fraud Orders",
  4: "DDoS",
  5: "FTP Brute-Force",
  6: "Ping of Death",
  7: "Phishing",
  8: "Fraud VoIP",
  9: "Open Proxy",
  10: "Web Spam",
  11: "Email Spam",
  12: "Blog Spam",
  13: "VPN IP",
  14: "Port Scan",
  15: "Hacking",
  16: "SQL Injection",
  17: "Spoofing",
  18: "Brute-Force",
  19: "Bad Web Bot",
  20: "Exploited Host",
  21: "Web App Attack",
  22: "SSH",
  23: "IoT Targeted",
};

function failure(status: number, error?: string, json?: unknown): ProviderOutcome {
  if (status === 401 || status === 403) {
    return { status: "error", detail: "The feed rejected the credential.", part: {} };
  }
  if (status === 429) return { status: "rate_limited", detail: "Upstream rate limit.", part: {} };
  if (status === 404) return { status: "empty", detail: "No record.", part: {} };
  const rec = asRecord(json);
  const message =
    asString(rec?.message) ??
    asString(asRecord(rec?.error)?.message) ??
    asString(rec?.verbose_msg) ??
    error ??
    (status ? `HTTP ${status}` : "Request failed");
  return { status: "error", detail: message.slice(0, 180), part: {} };
}

export async function queryIpinfo(
  ip: string,
  keys: FeedKeys,
  signal: AbortSignal,
): Promise<ProviderOutcome> {
  const token = keys.ipinfo;
  const url = token
    ? `https://ipinfo.io/${ip}?token=${encodeURIComponent(token)}`
    : `https://ipinfo.io/${ip}/json`;
  const main = await fetchJson(url, undefined, signal);
  if (!main.ok || !asRecord(main.json) || asRecord(main.json)?.error) {
    if (main.status === 429) return failure(429);
    return failure(main.status, main.error, main.json);
  }
  const body = asRecord(main.json) ?? {};
  let privacy = asRecord(body.privacy);
  if (!privacy && token) {
    const extra = await fetchJson(
      `https://ipinfo.io/${ip}/privacy?token=${encodeURIComponent(token)}`,
      undefined,
      signal,
    );
    if (extra.ok) privacy = asRecord(extra.json);
  }
  const asnObj = asRecord(body.asn);
  const org = asString(body.org) ?? "";
  const orgMatch = org.match(/^AS(\d+)\s+(.+)$/);
  const asn = asString(asnObj?.asn) ?? (orgMatch ? `AS${orgMatch[1]}` : undefined);
  const name = asString(asnObj?.name) ?? orgMatch?.[2] ?? (org && !orgMatch ? org : undefined);
  const countryCode = asString(body.country);
  return {
    status: "ok",
    detail: token ? "ipinfo with token" : "ipinfo free geo (privacy flags need a token)",
    part: {
      geo: {
        city: asString(body.city),
        region: asString(body.region),
        countryCode,
        country: countryCode,
        loc: asString(body.loc),
        timezone: asString(body.timezone),
        postal: asString(body.postal),
        hostname: asString(body.hostname),
        anycast: asBool(body.anycast),
        vpn: asBool(privacy?.vpn),
        proxy: asBool(privacy?.proxy),
        tor: asBool(privacy?.tor),
        relay: asBool(privacy?.relay),
        hosting: asBool(privacy?.hosting),
        privacyService: asString(privacy?.service),
      },
      asn: {
        asn,
        name,
        route: asString(asnObj?.route),
        domain: asString(asnObj?.domain),
        type: asString(asnObj?.type),
      },
    },
  };
}

export async function queryVirusTotal(
  ip: string,
  keys: FeedKeys,
  signal: AbortSignal,
): Promise<ProviderOutcome> {
  const key = keys.virustotal;
  if (!key) return { status: "no_key", detail: "Add a VirusTotal API key.", part: {} };
  const headers = { "x-apikey": key };
  const [report, resolutions] = await Promise.all([
    fetchJson(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, { headers }, signal),
    fetchJson(
      `https://www.virustotal.com/api/v3/ip_addresses/${ip}/resolutions?limit=8`,
      { headers },
      signal,
    ),
  ]);
  if (!report.ok) return failure(report.status, report.error, report.json);
  const data = asRecord(asRecord(report.json)?.data);
  const attr = asRecord(data?.attributes) ?? {};
  const stats = asRecord(attr.last_analysis_stats) ?? {};
  const results = asRecord(attr.last_analysis_results) ?? {};
  const engines = Object.entries(results)
    .map(([name, value]) => {
      const row = asRecord(value);
      return {
        name,
        category: asString(row?.category) ?? "unknown",
        result: asString(row?.result) ?? "",
      };
    })
    .filter((engine) => engine.category === "malicious" || engine.category === "suspicious")
    .slice(0, 24);
  const votes = asRecord(attr.total_votes);
  const rows = Array.isArray(asRecord(resolutions.json)?.data)
    ? (asRecord(resolutions.json)?.data as unknown[])
    : [];
  const passive = rows
    .map((row) => {
      const attributes = asRecord(asRecord(row)?.attributes);
      const hostname = asString(attributes?.host_name);
      if (!hostname) return null;
      return { hostname, lastSeen: unixToIso(attributes?.date) };
    })
    .filter((row): row is { hostname: string; lastSeen: string | undefined } => row !== null);

  const malicious = asNumber(stats.malicious) ?? 0;
  const suspicious = asNumber(stats.suspicious) ?? 0;
  const harmless = asNumber(stats.harmless) ?? 0;
  const undetected = asNumber(stats.undetected) ?? 0;
  const total = malicious + suspicious + harmless + undetected;
  return {
    status: total === 0 && engines.length === 0 ? "empty" : "ok",
    detail: total ? `${malicious} malicious / ${total} engines` : "No engine stats",
    part: {
      reputation: {
        malicious,
        suspicious,
        harmless,
        undetected,
        timeout: asNumber(stats.timeout) ?? 0,
        reputation: asNumber(attr.reputation) ?? null,
        tags: tagList(attr.tags),
        engines,
        lastAnalysis: unixToIso(attr.last_analysis_date),
        votesHarmless: asNumber(votes?.harmless),
        votesMalicious: asNumber(votes?.malicious),
        resolutions: passive,
      },
    },
  };
}

export async function queryAbuseIpdb(
  ip: string,
  keys: FeedKeys,
  signal: AbortSignal,
): Promise<ProviderOutcome> {
  const key = keys.abuseipdb;
  if (!key) return { status: "no_key", detail: "Add an AbuseIPDB API key.", part: {} };
  const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose=true`;
  const response = await fetchJson(url, { headers: { key, accept: "application/json" } }, signal);
  if (!response.ok) return failure(response.status, response.error, response.json);
  const data = asRecord(asRecord(response.json)?.data) ?? {};
  const reports = Array.isArray(data.reports) ? data.reports : [];
  const counts = new Map<string, number>();
  const recent = reports.slice(0, 6).map((report) => {
    const row = asRecord(report) ?? {};
    const ids = Array.isArray(row.categories) ? row.categories : [];
    const categories = ids
      .map((id) => ABUSE_CATEGORIES[Number(id)] ?? `Category ${String(id)}`)
      .filter(Boolean);
    for (const category of categories) counts.set(category, (counts.get(category) ?? 0) + 1);
    return {
      reportedAt: asString(row.reportedAt),
      comment: asString(row.comment)?.slice(0, 180),
      categories,
    };
  });
  if (reports.length > 6) {
    for (const report of reports.slice(6)) {
      const ids = Array.isArray(asRecord(report)?.categories) ? (asRecord(report)?.categories as unknown[]) : [];
      for (const id of ids) {
        const name = ABUSE_CATEGORIES[Number(id)] ?? `Category ${String(id)}`;
        counts.set(name, (counts.get(name) ?? 0) + 1);
      }
    }
  }
  const score = asNumber(data.abuseConfidenceScore) ?? 0;
  const totalReports = asNumber(data.totalReports) ?? 0;
  return {
    status: "ok",
    detail: `Confidence ${score}, ${totalReports} reports`,
    part: {
      abuse: {
        score,
        totalReports,
        distinctReporters: asNumber(data.numDistinctUsers),
        lastReportedAt: asString(data.lastReportedAt),
        usageType: asString(data.usageType),
        isp: asString(data.isp),
        domain: asString(data.domain),
        categories: [...counts.entries()]
          .map(([name, count]) => ({ name, count }))
          .sort((a, b) => b.count - a.count)
          .slice(0, 8),
        recent,
      },
    },
  };
}

function parseGreyNoise(json: unknown) {
  const body = asRecord(json) ?? {};
  const scanner =
    asRecord(body.internet_scanner_intelligence) ?? asRecord(body.scanner_intelligence) ?? {};
  const business =
    asRecord(body.business_service_intelligence) ?? asRecord(body.business_intelligence) ?? {};
  const noise = asBool(body.noise) ?? (scanner.found === true ? true : scanner.found === false ? false : null);
  const riot = asBool(body.riot) ?? (business.found === true ? true : business.found === false ? false : null);
  let classification = (asString(body.classification) ?? asString(scanner.classification) ?? "").toLowerCase();
  if (!classification) {
    if (riot) classification = "benign";
    else if (noise) classification = "unknown";
    else classification = "unseen";
  }
  const tags = unique([...tagList(body.tags), ...tagList(scanner.tags), ...tagList(body.raw_data)]);
  const rawName = asString(body.name) ?? asString(business.name) ?? asString(scanner.organization);
  const name = rawName && !/^unknown$/i.test(rawName) ? rawName : undefined;
  return {
    noise,
    riot,
    classification,
    name,
    actor: asString(body.actor) ?? asString(scanner.actor),
    tags,
    lastSeen: asString(body.last_seen) ?? asString(scanner.last_seen),
    link: asString(body.link),
    message: asString(body.message),
    spoofable: asBool(scanner.spoofable) ?? asBool(body.spoofable),
    vpn: asBool(scanner.vpn) ?? asBool(body.vpn),
  };
}

export async function queryGreyNoise(
  ip: string,
  version: 4 | 6,
  keys: FeedKeys,
  signal: AbortSignal,
): Promise<ProviderOutcome> {
  if (version === 6 && !keys.greynoise) {
    return {
      status: "unsupported",
      detail: "Community GreyNoise is IPv4-only and does not include RIOT (known services).",
      part: {},
    };
  }
  const headers: Record<string, string> = {};
  const url = keys.greynoise
    ? `https://api.greynoise.io/v3/ip/${ip}`
    : `https://api.greynoise.io/v3/community/${ip}`;
  if (keys.greynoise) headers.key = keys.greynoise;
  const response = await fetchJson(url, { headers }, signal);
  if (response.status === 401 || response.status === 403) {
    return keys.greynoise
      ? { status: "error", detail: "GreyNoise rejected the API key.", part: {} }
      : { status: "no_key", detail: "GreyNoise now requires an API key.", part: {} };
  }
  if (response.status === 400) {
    return { status: "unsupported", detail: "GreyNoise could not query this address.", part: {} };
  }
  if (response.status === 429) return failure(429);
  if (!response.json || (response.status >= 500 && !asRecord(response.json)?.message)) {
    return failure(response.status, response.error, response.json);
  }
  const parsed = { ...parseGreyNoise(response.json), coverage: keys.greynoise ? ("full" as const) : ("community" as const) };
  return {
    status: "ok",
    detail: keys.greynoise
      ? `GreyNoise v3 · ${parsed.classification}`
      : `Community · ${parsed.classification}. RIOT is not included.`,
    part: { greynoise: parsed },
  };
}

export async function queryShodan(
  ip: string,
  keys: FeedKeys,
  signal: AbortSignal,
): Promise<ProviderOutcome> {
  const internet = await fetchJson(`https://internetdb.shodan.io/${ip}`, undefined, signal);
  const internetBody = internet.status === 404 ? null : asRecord(internet.json);
  let host: Record<string, unknown> | null = null;
  let honeyScore: number | null = null;
  let hostError: ProviderOutcome | null = null;
  if (keys.shodan) {
    const key = encodeURIComponent(keys.shodan);
    const [hostRes, honeyRes] = await Promise.all([
      fetchJson(`https://api.shodan.io/shodan/host/${ip}?key=${key}`, undefined, signal),
      fetchJson(`https://api.shodan.io/labs/honeyscore/${ip}?key=${key}`, undefined, signal),
    ]);
    if (hostRes.ok) host = asRecord(hostRes.json);
    else if (hostRes.status !== 404) hostError = failure(hostRes.status, hostRes.error, hostRes.json);
    if (typeof honeyRes.json === "number") honeyScore = honeyRes.json;
    else honeyScore = asNumber(honeyRes.json) ?? null;
  }

  if (!host && !internetBody) {
    if (hostError) return hostError;
    if (!internet.ok && internet.status !== 404) return failure(internet.status, internet.error, internet.json);
    return {
      status: "empty",
      detail: keys.shodan
        ? "No Shodan host record and nothing in InternetDB."
        : "Nothing in Shodan InternetDB. A Shodan key adds banners and honeypot score.",
      part: {
        shodan: {
          ports: [],
          hostnames: [],
          tags: [],
          vulns: [],
          vulnCount: 0,
          cpes: [],
          honeypot: keys.shodan ? false : null,
          honeyScore,
          services: [],
          provenance: keys.shodan ? "Shodan host API" : "Shodan InternetDB",
        },
      },
    };
  }

  const ports = new Set<number>();
  const hostnames: string[] = [];
  const tags: string[] = [];
  const vulns: string[] = [];
  const cpes: string[] = [];
  for (const port of [...(Array.isArray(internetBody?.ports) ? internetBody.ports : []), ...(Array.isArray(host?.ports) ? host.ports : [])]) {
    const n = typeof port === "number" ? port : Number(port);
    if (Number.isInteger(n)) ports.add(n);
  }
  hostnames.push(...tagList(internetBody?.hostnames), ...tagList(host?.hostnames));
  tags.push(...tagList(internetBody?.tags), ...tagList(host?.tags));
  if (Array.isArray(internetBody?.vulns)) vulns.push(...tagList(internetBody.vulns));
  if (host?.vulns && typeof host.vulns === "object") vulns.push(...Object.keys(host.vulns as object));
  cpes.push(...tagList(internetBody?.cpes));

  const services = (Array.isArray(host?.data) ? host.data : []).slice(0, 8).map((row) => {
    const rec = asRecord(row) ?? {};
    const banner = asString(rec.data)?.replace(/\s+\n/g, "\n").slice(0, 420);
    const cpe = tagList(rec.cpe);
    cpes.push(...cpe);
    return {
      port: asNumber(rec.port) ?? 0,
      transport: asString(rec.transport),
      product: asString(rec.product),
      version: asString(rec.version),
      banner,
    };
  });

  const vulnSeen = new Set<string>();
  const vulnList: string[] = [];
  for (const vuln of vulns) {
    const key = vuln.toLowerCase();
    if (!vuln || vulnSeen.has(key)) continue;
    vulnSeen.add(key);
    vulnList.push(vuln);
  }
  const products = unique(
    services.map((service) => [service.product, service.version].filter(Boolean).join(" ")).filter(Boolean),
    6,
  );
  const os = asString(host?.os);
  const honeypot =
    honeyScore !== null
      ? honeyScore >= 0.5
      : tags.some((tag) => /honeypot/i.test(tag))
        ? true
        : keys.shodan
          ? false
          : null;

  return {
    status: "ok",
    detail: host
      ? internetBody
        ? "Shodan host API + InternetDB"
        : "Shodan host API"
      : "Shodan InternetDB (no API key — banners and honeypot score need a key)",
    part: {
      shodan: {
        ports: [...ports].sort((a, b) => a - b),
        hostnames: unique(hostnames, 8),
        tags: unique(tags, 12),
        vulns: vulnList.slice(0, 16),
        vulnCount: vulnList.length,
        cpes: unique(cpes, 12),
        os,
        org: asString(host?.org),
        lastUpdate: asString(host?.last_update),
        honeypot,
        honeyScore,
        services,
        fingerprint: [os, ...products].filter(Boolean).join(" · ") || undefined,
        provenance: host ? "Shodan" : "InternetDB",
      },
    },
  };
}

function vcardRows(vcardArray: unknown): unknown[][] {
  if (!Array.isArray(vcardArray) || vcardArray[0] !== "vcard" || !Array.isArray(vcardArray[1])) return [];
  return vcardArray[1].filter((row) => Array.isArray(row)) as unknown[][];
}

function vcardValue(rows: unknown[][], name: string): string | undefined {
  for (const row of rows) {
    if (String(row[0]).toLowerCase() !== name) continue;
    const value = row[3];
    if (typeof value === "string" && value.trim()) return value.trim().replace(/^mailto:/i, "");
  }
  return undefined;
}

type WhoisAcc = {
  registrar?: string;
  provider?: string;
  abuseEmails: string[];
  abusePhones: string[];
};

function walkEntities(entities: unknown[], acc: WhoisAcc) {
  for (const entity of entities) {
    const rec = asRecord(entity);
    if (!rec) continue;
    const roles = Array.isArray(rec.roles) ? rec.roles.map((role) => String(role).toLowerCase()) : [];
    const rows = vcardRows(rec.vcardArray);
    const email = vcardValue(rows, "email");
    const phone = vcardValue(rows, "tel");
    const name = vcardValue(rows, "fn");
    const handle = asString(rec.handle) ?? "";
    if (roles.includes("registrar") && name) acc.registrar = name;
    if ((roles.includes("registrant") || roles.includes("administrative")) && name && !acc.provider) {
      acc.provider = name;
    }
    const abuse = roles.includes("abuse") || /abuse/i.test(handle);
    if (abuse && email) acc.abuseEmails.push(email);
    if (abuse && phone) acc.abusePhones.push(phone);
    if (Array.isArray(rec.entities)) walkEntities(rec.entities, acc);
  }
}

function registryFrom(port43: string | undefined, href: string | undefined): string | undefined {
  const blob = `${port43 ?? ""} ${href ?? ""}`.toLowerCase();
  if (blob.includes("arin")) return "ARIN";
  if (blob.includes("ripe")) return "RIPE NCC";
  if (blob.includes("apnic")) return "APNIC";
  if (blob.includes("lacnic")) return "LACNIC";
  if (blob.includes("afrinic")) return "AFRINIC";
  return undefined;
}

export async function queryWhois(ip: string, signal: AbortSignal): Promise<ProviderOutcome> {
  const [rdap, ripeAbuse, ripeNet] = await Promise.all([
    fetchJson(`https://rdap.org/ip/${ip}`, undefined, signal, 14000),
    fetchJson(
      `https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=${encodeURIComponent(ip)}`,
      undefined,
      signal,
    ),
    fetchJson(
      `https://stat.ripe.net/data/network-info/data.json?resource=${encodeURIComponent(ip)}`,
      undefined,
      signal,
    ),
  ]);

  const body = asRecord(rdap.json);
  const rdapOk = rdap.ok && body && (body.objectClassName || body.handle || body.startAddress);
  if (!rdapOk && !ripeNet.ok && !ripeAbuse.ok) {
    return failure(rdap.status || ripeNet.status, rdap.error, rdap.json);
  }

  const acc: WhoisAcc = { abuseEmails: [], abusePhones: [] };
  if (rdapOk && body) {
    if (Array.isArray(body.entities)) walkEntities(body.entities, acc);
  }
  const abuseData = asRecord(asRecord(ripeAbuse.json)?.data);
  const ripeEmails = Array.isArray(abuseData?.abuse_contacts) ? abuseData.abuse_contacts : [];
  for (const email of ripeEmails) {
    if (typeof email === "string") acc.abuseEmails.push(email);
  }
  const net = asRecord(asRecord(ripeNet.json)?.data);
  const asnNum = Array.isArray(net?.asns) ? net.asns[0] : undefined;
  const prefix = asString(net?.prefix);
  const cidrs = Array.isArray(body?.cidr0_cidrs) ? body.cidr0_cidrs : [];
  const firstCidr = asRecord(cidrs[0]);
  const cidr =
    prefix ??
    (firstCidr?.v4prefix && firstCidr.length
      ? `${String(firstCidr.v4prefix)}/${String(firstCidr.length)}`
      : firstCidr?.v6prefix && firstCidr.length
        ? `${String(firstCidr.v6prefix)}/${String(firstCidr.length)}`
        : undefined);
  const events = Array.isArray(body?.events) ? body.events : [];
  let registered: string | undefined;
  let updated: string | undefined;
  for (const event of events) {
    const rec = asRecord(event);
    const action = asString(rec?.eventAction)?.toLowerCase();
    const date = asString(rec?.eventDate);
    if (action === "registration") registered = date;
    if (action === "last changed") updated = date;
  }
  const remarks = Array.isArray(body?.remarks) ? body.remarks : [];
  const excerpt = remarks
    .flatMap((remark) => {
      const description = asRecord(remark)?.description;
      return Array.isArray(description) ? description.map((line) => String(line)) : [];
    })
    .join(" ")
    .replace(/\s+/g, " ")
    .slice(0, 320);
  const links = Array.isArray(body?.links) ? body.links : [];
  const self = asString(asRecord(links[0])?.href);
  const registry =
    registryFrom(asString(body?.port43), self) ??
    (asString(abuseData?.authoritative_rir)?.toUpperCase() || undefined);
  const start = asString(body?.startAddress);
  const end = asString(body?.endAddress);
  const emails = unique(acc.abuseEmails, 6);
  const phones = unique(acc.abusePhones, 4);

  return {
    status: "ok",
    detail: registry ? `${registry} via RDAP` : "RDAP / RIPEstat",
    part: {
      whois: {
        registry,
        name: asString(body?.name),
        handle: asString(body?.handle),
        cidr,
        range: start && end ? `${start} – ${end}` : undefined,
        country: asString(body?.country),
        provider: acc.provider,
        registrar: acc.registrar,
        abuseEmails: emails,
        abusePhones: phones,
        status: Array.isArray(body?.status) ? body.status.map((item) => String(item)).slice(0, 6) : [],
        registered,
        updated,
        excerpt: excerpt || undefined,
      },
      geo: asString(body?.country) ? { countryCode: asString(body?.country) } : undefined,
      asn: asnNum
        ? { asn: `AS${String(asnNum)}`, route: prefix }
        : prefix
          ? { route: prefix }
          : undefined,
    },
  };
}

export async function queryOtx(
  ip: string,
  version: 4 | 6,
  keys: FeedKeys,
  signal: AbortSignal,
): Promise<ProviderOutcome> {
  const key = keys.otx;
  if (!key) return { status: "no_key", detail: "Add an AlienVault OTX API key.", part: {} };
  const kind = version === 4 ? "IPv4" : "IPv6";
  const headers = { "X-OTX-API-KEY": key };
  const [general, malware] = await Promise.all([
    fetchJson(`https://otx.alienvault.com/api/v1/indicators/${kind}/${ip}/general`, { headers }, signal),
    fetchJson(`https://otx.alienvault.com/api/v1/indicators/${kind}/${ip}/malware`, { headers }, signal),
  ]);
  if (general.status === 401 || general.status === 403) {
    return { status: "error", detail: "OTX rejected the API key.", part: {} };
  }
  if (!general.ok && general.status !== 404) return failure(general.status, general.error, general.json);
  const body = asRecord(general.json) ?? {};
  const pulseInfo = asRecord(body.pulse_info) ?? {};
  const pulsesRaw = Array.isArray(pulseInfo.pulses) ? pulseInfo.pulses : [];
  const families: string[] = [];
  const adversaries: string[] = [];
  const tags: string[] = [];
  const pulses = pulsesRaw.slice(0, 8).map((pulse) => {
    const rec = asRecord(pulse) ?? {};
    const pulseFamilies = (Array.isArray(rec.malware_families) ? rec.malware_families : [])
      .map((family) => {
        if (typeof family === "string") return family;
        const row = asRecord(family);
        return asString(row?.display_name) ?? asString(row?.name) ?? "";
      })
      .filter(Boolean);
    families.push(...pulseFamilies);
    const adversary = asString(rec.adversary);
    if (adversary) adversaries.push(adversary);
    const pulseTags = tagList(rec.tags);
    tags.push(...pulseTags);
    return {
      name: asString(rec.name) ?? "Untitled pulse",
      tags: pulseTags.slice(0, 6),
      adversary,
      malwareFamilies: pulseFamilies.slice(0, 6),
      modified: asString(rec.modified),
    };
  });
  const dnsRows = Array.isArray(asRecord(body.passive_dns)?.passive_dns)
    ? (asRecord(body.passive_dns)?.passive_dns as unknown[])
    : Array.isArray(body.passive_dns)
      ? body.passive_dns
      : [];
  const passiveDns = dnsRows
    .map((row) => {
      const rec = asRecord(row);
      const hostname = asString(rec?.hostname) ?? asString(rec?.address);
      if (!hostname) return null;
      return { hostname, lastSeen: asString(rec?.last) ?? asString(rec?.last_seen) };
    })
    .filter((row): row is { hostname: string; lastSeen: string | undefined } => row !== null)
    .slice(0, 8);
  const samplesRaw = Array.isArray(asRecord(malware.json)?.data) ? (asRecord(malware.json)?.data as unknown[]) : [];
  const samples = samplesRaw.slice(0, 5).map((sample) => {
    const rec = asRecord(sample) ?? {};
    return {
      hash: asString(rec.hash) ?? asString(rec.sha256) ?? asString(rec.md5) ?? "unknown",
      date: asString(rec.date) ?? asString(rec.datetime),
    };
  });
  const pulseCount = asNumber(pulseInfo.count) ?? pulsesRaw.length;
  return {
    status: pulseCount === 0 ? "empty" : "ok",
    detail: pulseCount ? `${pulseCount} pulses` : "No OTX pulses",
    part: {
      otx: {
        pulseCount,
        pulses,
        malwareFamilies: unique(families, 8),
        adversaries: unique(adversaries, 6),
        tags: unique(tags, 12),
        passiveDns,
        samples: samples.filter((sample) => sample.hash !== "unknown"),
      },
    },
  };
}

type TokenEntry = { token: string; exp: number };
const mdtiTokens = new Map<string, TokenEntry>();

async function mdtiToken(keys: FeedKeys, signal: AbortSignal): Promise<{ token?: string; error?: string }> {
  const tenant = keys.mdtiTenant ?? "";
  const clientId = keys.mdtiClientId ?? "";
  const secret = keys.mdtiClientSecret ?? "";
  if (!/^[A-Za-z0-9.-]{3,80}$/.test(tenant)) {
    return { error: "MDTI tenant id looks invalid." };
  }
  const cacheKey = `${tenant}:${clientId}`;
  const cached = mdtiTokens.get(cacheKey);
  if (cached && cached.exp > Date.now() + 30_000) return { token: cached.token };
  const body = new URLSearchParams({
    client_id: clientId,
    client_secret: secret,
    scope: "https://graph.microsoft.com/.default",
    grant_type: "client_credentials",
  });
  const response = await fetchJson(
    `https://login.microsoftonline.com/${encodeURIComponent(tenant)}/oauth2/v2.0/token`,
    { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body },
    signal,
  );
  const json = asRecord(response.json);
  const token = asString(json?.access_token);
  if (!response.ok || !token) {
    const message = asString(json?.error_description) ?? asString(json?.error) ?? response.error ?? "Token request failed";
    return { error: message.slice(0, 180) };
  }
  const expires = asNumber(json?.expires_in) ?? 3600;
  mdtiTokens.set(cacheKey, { token, exp: Date.now() + expires * 1000 });
  return { token };
}

export async function queryMdti(
  ip: string,
  keys: FeedKeys,
  signal: AbortSignal,
): Promise<ProviderOutcome> {
  if (!keys.mdtiTenant || !keys.mdtiClientId || !keys.mdtiClientSecret) {
    return {
      status: "no_key",
      detail: "Defender TI needs a tenant id, client id, and client secret.",
      part: {},
    };
  }
  const auth = await mdtiToken(keys, signal);
  if (!auth.token) return { status: "error", detail: auth.error ?? "Could not sign in to Microsoft Graph.", part: {} };
  const headers = { authorization: `Bearer ${auth.token}` };
  const hostId = encodeURIComponent(ip);
  const [hostRes, repRes] = await Promise.all([
    fetchJson(
      `https://graph.microsoft.com/v1.0/security/threatIntelligence/hosts/${hostId}`,
      { headers },
      signal,
    ),
    fetchJson(
      `https://graph.microsoft.com/v1.0/security/threatIntelligence/hosts/${hostId}/reputation`,
      { headers },
      signal,
    ),
  ]);
  if (repRes.status === 401 || repRes.status === 403 || hostRes.status === 401 || hostRes.status === 403) {
    return {
      status: "error",
      detail: "Graph rejected the app. It needs ThreatIntelligence.Read.All and an MDTI API license.",
      part: {},
    };
  }
  if ((repRes.status === 404 || !repRes.ok) && (hostRes.status === 404 || !hostRes.ok) && repRes.status !== 429) {
    if (repRes.status === 429 || hostRes.status === 429) return failure(429);
    if (!repRes.ok && repRes.status !== 404) return failure(repRes.status, repRes.error, repRes.json);
    return { status: "empty", detail: "Defender TI has no host record.", part: {} };
  }
  const rep = asRecord(repRes.json) ?? {};
  const host = asRecord(hostRes.json) ?? {};
  const rulesRaw = Array.isArray(rep.rules) ? rep.rules : [];
  const rules = rulesRaw.slice(0, 8).map((rule) => {
    const rec = asRecord(rule) ?? {};
    return {
      name: asString(rec.name) ?? "Rule",
      description: asString(rec.description)?.slice(0, 220),
      severity: asString(rec.severity),
      url: asString(rec.relatedDetailsUrl),
    };
  });
  const classification = asString(rep.classification);
  return {
    status: classification || rules.length ? "ok" : "empty",
    detail: classification ? `Classification ${classification}` : "Host record without a reputation score",
    part: {
      mdti: {
        classification,
        score: asNumber(rep.score) ?? null,
        rules,
        firstSeen: asString(host.firstSeenDateTime),
        lastSeen: asString(host.lastSeenDateTime),
      },
    },
  };
}

const SPAMHAUS: Record<string, string> = {
  "127.0.0.2": "SBL",
  "127.0.0.3": "CSS",
  "127.0.0.4": "XBL",
  "127.0.0.9": "DROP",
  "127.0.0.10": "PBL",
  "127.0.0.11": "PBL",
};

function expandIpv6(ip: string): string | null {
  if (ip.includes(".")) return null;
  const halves = ip.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":").filter(Boolean) : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":").filter(Boolean) : [];
  if (halves.length === 1) {
    if (head.length !== 8) return null;
    return head.map((part) => part.padStart(4, "0")).join(":");
  }
  const missing = 8 - head.length - tail.length;
  if (missing < 0) return null;
  return [...head, ...Array(missing).fill("0"), ...tail].map((part) => part.padStart(4, "0")).join(":");
}

function spamhausName(ip: string, version: 4 | 6): string | null {
  if (version === 4) return `${ip.split(".").reverse().join(".")}.zen.spamhaus.org`;
  const expanded = expandIpv6(ip);
  if (!expanded) return null;
  const nibbles = expanded.replace(/:/g, "").split("").reverse().join(".");
  return `${nibbles}.zen.spamhaus.org`;
}

function errorCode(error: unknown): string {
  if (error && typeof error === "object" && "code" in error && typeof error.code === "string") return error.code;
  return "";
}

export async function querySpamhaus(ip: string, version: 4 | 6): Promise<ProviderOutcome> {
  const name = spamhausName(ip, version);
  if (!name) {
    return {
      status: "unsupported",
      detail: "Spamhaus DNSBL does not cover this address shape.",
      part: { blocklist: { spamhaus: { listed: false, status: "unavailable", codes: [] } } },
    };
  }
  try {
    const answers = await dns.resolve4(name);
    const codes = unique(
      answers.map((answer) => {
        if (answer.startsWith("127.255.")) return "QUERY-BLOCKED";
        return SPAMHAUS[answer] ?? answer;
      }),
    );
    if (codes.includes("QUERY-BLOCKED")) {
      return {
        status: "error",
        detail: "Spamhaus refused the DNS query from this resolver.",
        part: {
          blocklist: {
            spamhaus: { listed: false, status: "unavailable", codes: [], detail: "Resolver policy block" },
          },
        },
      };
    }
    return {
      status: "ok",
      detail: `Listed: ${codes.join(", ")}`,
      part: { blocklist: { spamhaus: { listed: true, status: "listed", codes } } },
    };
  } catch (error) {
    const code = errorCode(error);
    if (code === "ENOTFOUND" || code === "ENODATA" || code === "ENOENT") {
      return {
        status: "ok",
        detail: "Not listed on Spamhaus ZEN",
        part: { blocklist: { spamhaus: { listed: false, status: "clean", codes: [] } } },
      };
    }
    return {
      status: "error",
      detail: "Spamhaus DNS lookup failed.",
      part: {
        blocklist: { spamhaus: { listed: false, status: "unavailable", codes: [], detail: code || "lookup failed" } },
      },
    };
  }
}

export const PROVIDER_ORDER: FeedId[] = [
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
