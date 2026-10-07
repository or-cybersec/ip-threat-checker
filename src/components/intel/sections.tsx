import * as Collapsible from "@radix-ui/react-collapsible";
import { ChevronDown } from "lucide-react";
import { useEffect, useRef, useState, type ReactNode } from "react";

import { JsonView } from "@/components/intel/json-view";
import { InfoTip } from "@/components/intel/info-tip";
import type {
  Asn,
  Finding,
  Geo,
  GreyNoise,
  PassiveDns,
  Reputation,
  Shodan,
  SourceMeta,
  TimelineEvent,
  Verdict,
  Whois,
} from "@/lib/intel/types";

const RISKY = new Set([21, 22, 23, 25, 445, 1433, 2375, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017, 31337]);

export type Phase = "idle" | "running" | "done" | "error";

type FeedSlice = {
  phase: Phase;
  source?: SourceMeta;
  keyed?: boolean;
  children: ReactNode;
  empty?: string;
};

function Spinner() {
  return (
    <span
      className="inline-block size-4 animate-spin rounded-full border-2 border-line border-t-accent"
      aria-hidden="true"
    />
  );
}

function cacheAge(iso?: string): string {
  if (!iso) return "cached";
  const ms = Date.now() - Date.parse(iso);
  if (!Number.isFinite(ms) || ms < 45_000) return "cached <1m";
  const minutes = Math.round(ms / 60_000);
  if (minutes < 60) return `cached ${minutes}m`;
  return `cached ${Math.round(minutes / 60)}h`;
}

export function sourceWord(source: SourceMeta): string {
  const age = source.cached ? cacheAge(source.cachedAt) : "";
  if (source.status === "rate_limited") return age ? `limited · ${age}` : "limited";
  if (source.status === "ok") return age || "live";
  if (source.status === "empty") return age ? `no hit · ${age}` : "no hit";
  if (source.status === "error") return "error";
  if (source.status === "no_key") return "no key";
  if (source.status === "unsupported") return "skipped";
  return source.status;
}

function statusClass(source: SourceMeta): string {
  if (source.status === "error") return "text-critical";
  if (source.status === "no_key" || source.status === "rate_limited") return "text-warn";
  if (source.cached) return "text-muted";
  if (source.status === "ok") return "text-ok";
  return "text-muted";
}

export function FeedSlot({ phase, source, keyed, children, empty }: FeedSlice) {
  if (!source && phase === "running") {
    return (
      <p className="flex items-center gap-2 text-sm text-muted">
        <Spinner />
        Querying…
      </p>
    );
  }
  if (!source) {
    return <p className="text-sm text-muted">Run a lookup to fill this section.</p>;
  }
  if (source.status === "no_key") {
    return <p className="text-sm text-muted">{source.detail ?? "This feed needs a credential."}</p>;
  }
  if (source.status === "error") {
    return <p className="text-sm text-critical">{source.detail ?? "This feed did not respond."}</p>;
  }
  if (source.status === "rate_limited" || source.status === "unsupported") {
    return <p className="text-sm text-warn">{source.detail ?? "This feed did not respond."}</p>;
  }
  if (empty && source.status === "empty" && !keyed) {
    return <p className="text-sm text-muted">{source.detail ?? empty}</p>;
  }
  return (
    <div className="grid gap-4">
      {source.detail ? (
        <p className="text-xs text-faint">
          {source.detail}
          {source.cached ? ` · ${cacheAge(source.cachedAt)}` : ""} · {source.ms} ms
        </p>
      ) : null}
      {children}
    </div>
  );
}

function answered(source?: SourceMeta): boolean {
  return source?.status === "ok" || source?.status === "empty" || source?.status === "rate_limited" || source?.status === "error";
}

export function Section({
  id,
  title,
  source,
  info,
  defaultOpen = true,
  children,
}: {
  id: string;
  title: string;
  source?: SourceMeta;
  info?: string;
  defaultOpen?: boolean;
  children: ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const revealed = useRef(defaultOpen);
  useEffect(() => {
    if (defaultOpen && !revealed.current) {
      revealed.current = true;
      setOpen(true);
    }
  }, [defaultOpen]);
  return (
    <Collapsible.Root id={id} open={open} onOpenChange={setOpen} className="scroll-mt-24 rounded-lg border border-line bg-surface">
      <div className="flex items-stretch">
        <Collapsible.Trigger className="flex min-h-11 min-w-0 flex-1 items-center gap-3 px-4 py-3 text-left">
          <span className="flex-1 text-sm font-semibold">{title}</span>
          {source ? (
            <span className={`font-mono text-xs ${statusClass(source)}`}>{sourceWord(source)}</span>
          ) : null}
          <ChevronDown className={`size-4 text-muted transition-transform ${open ? "rotate-180" : ""}`} />
        </Collapsible.Trigger>
        {info ? (
          <div className="flex items-center pr-1">
            <InfoTip label={`${title} explanation`} text={info} />
          </div>
        ) : null}
      </div>
      <Collapsible.Content className="border-t border-line px-4 py-4">{children}</Collapsible.Content>
    </Collapsible.Root>
  );
}

function Meta({ label, value }: { label: string; value?: string | number | boolean | null }) {
  const text =
    value === undefined || value === null || value === ""
      ? "—"
      : typeof value === "boolean"
        ? value
          ? "Yes"
          : "No"
        : String(value);
  return (
    <div className="min-w-0">
      <p className="text-xs text-faint">{label}</p>
      <p className="font-mono text-sm break-words text-fg">{text}</p>
    </div>
  );
}

function regionName(code?: string): string | undefined {
  if (!code) return undefined;
  if (code.length !== 2) return code;
  try {
    return new Intl.DisplayNames(["en"], { type: "region" }).of(code.toUpperCase()) ?? code;
  } catch {
    return code;
  }
}

const findingBar: Record<Verdict, string> = {
  critical: "border-critical",
  suspicious: "border-warn",
  benign: "border-ok",
  unknown: "border-line",
};

export function Overview({
  ip,
  version,
  geo,
  asn,
  cgnat,
  assetNote,
  tags,
  findings,
  verdict,
  score,
  phase,
}: {
  ip: string;
  version?: 4 | 6;
  geo: Geo;
  asn: Asn;
  cgnat?: boolean;
  assetNote?: string | null;
  tags: string[];
  findings: Finding[];
  verdict?: Verdict;
  score?: number;
  phase: Phase;
}) {
  const country = regionName(geo.countryCode) ?? regionName(geo.country) ?? geo.country;
  const place = [geo.city, geo.region, country].filter(Boolean).join(", ");
  const ring =
    verdict === "critical" ? "ring-critical" : verdict === "suspicious" ? "ring-warn" : verdict === "benign" ? "ring-ok" : "ring-muted";
  const [lat, lon] = (geo.loc ?? "").split(",");
  const facts = [
    ["Hostname", geo.hostname],
    ["Coordinates", lat && lon ? `${lat}, ${lon}` : undefined],
    ["Timezone", geo.timezone],
    ["Network", asn.route],
    ["VPN", geo.vpn],
    ["Proxy", geo.proxy],
    ["Tor", geo.tor],
    ["Hosting", geo.hosting],
  ].filter((entry): entry is [string, string | boolean] => entry[1] !== undefined && entry[1] !== "");

  return (
    <section id="overview" className="scroll-mt-24 rounded-lg border border-line bg-surface p-4">
      <div className="flex flex-wrap items-start gap-5">
        <div className={`grid size-24 shrink-0 place-items-center rounded-full score-ring ${ring}`} style={{ ["--p" as string]: String(score ?? 0) }}>
          <div className="grid size-20 place-items-center rounded-full bg-surface">
            {phase === "running" && score === undefined ? (
              <span className="inline-block size-5 animate-spin rounded-full border-2 border-line border-t-accent" />
            ) : (
              <span className="font-mono text-2xl font-medium tabular-nums">{score ?? "–"}</span>
            )}
          </div>
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <VerdictPill verdict={verdict} phase={phase} />
            <InfoTip label="How to read the score" text={scoreTip(verdict, phase)} />
            {version ? <span className="font-mono text-xs text-faint">IPv{version}</span> : null}
          </div>
          <p className="mt-2 text-sm text-pretty text-fg">{plainVerdict(verdict, phase)}</p>
          <p className="mt-2 font-mono text-xl break-all text-fg sm:text-2xl">{ip || "No address yet"}</p>
          <SourceLinks ip={ip} />
          <p className="mt-1 text-sm text-pretty text-muted">
            {place || (phase === "running" ? "Waiting for geolocation…" : "Public IP, reputation, and exposure in one pass.")}
            {asn.asn ? ` · ${asn.asn}${asn.name ? ` ${asn.name}` : ""}` : ""}
          </p>
          {tags.length ? (
            <ul className="mt-3 flex flex-wrap gap-1.5">
              {tags.map((tag) => (
                <li key={tag} className="rounded-sm bg-raised px-2 py-0.5 font-mono text-xs text-muted">
                  {tag}
                </li>
              ))}
            </ul>
          ) : null}
        </div>
      </div>
      {facts.length ? (
        <dl className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
          {facts.map(([label, value]) => (
            <Meta key={label} label={label} value={value} />
          ))}
        </dl>
      ) : null}
      {cgnat ? <p className="mt-3 text-sm text-warn">Carrier-grade NAT. Any reputation is shared by many subscribers.</p> : null}
      {assetNote ? <p className="mt-3 text-sm text-fg">{assetNote}</p> : null}
      {findings.length ? (
        <ul className="mt-4 grid gap-2">
          {findings.map((finding) => (
            <li key={finding.text} className={`border-l-2 pl-3 text-sm text-pretty ${findingBar[finding.level]}`}>
              {finding.text}
              {finding.points ? (
                <span className="ml-2 font-mono text-xs text-faint tabular-nums">
                  {finding.points > 0 ? `+${finding.points}` : `−${Math.abs(finding.points)}`}
                </span>
              ) : null}
            </li>
          ))}
        </ul>
      ) : null}
      {score === 0 && findings.some((finding) => (finding.points ?? 0) < 0) ? (
        <p className="mt-2 text-xs text-faint">A clean finding cannot make the score negative.</p>
      ) : null}
    </section>
  );
}

function SourceLinks({ ip }: { ip: string }) {
  if (!/^(?:\d{1,3}\.){3}\d{1,3}$/.test(ip) && !/^[0-9a-f:]+$/i.test(ip)) return null;
  const links = [
    ["VirusTotal", `https://www.virustotal.com/gui/ip-address/${ip}`],
    ["AbuseIPDB", `https://www.abuseipdb.com/check/${ip}`],
    ["Shodan", `https://www.shodan.io/host/${ip}`],
    ["RDAP", `https://rdap.org/ip/${ip}`],
  ];
  return (
    <ul className="mt-3 flex flex-wrap gap-2">
      {links.map(([label, href]) => (
        <li key={label}>
          <a
            href={href}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex h-8 items-center rounded-md border border-line px-2 text-xs text-muted hover:text-fg"
          >
            {label}
          </a>
        </li>
      ))}
    </ul>
  );
}

function VerdictPill({ verdict, phase }: { verdict?: Verdict; phase: Phase }) {
  if (!verdict) {
    return (
      <span className="rounded-sm bg-raised px-2 py-1 font-mono text-xs tracking-wide text-muted">
        {phase === "running" ? "SCORING" : phase === "error" ? "FAILED" : "STANDBY"}
      </span>
    );
  }
  const tone =
    verdict === "critical"
      ? "bg-critical-dim text-critical"
      : verdict === "suspicious"
        ? "bg-warn-dim text-warn"
        : verdict === "benign"
          ? "bg-ok-dim text-ok"
          : "bg-raised text-muted";
  return <span className={`rounded-sm px-2 py-1 font-mono text-xs tracking-wide ${tone}`}>{verdict.toUpperCase()}</span>;
}

export function ReputationPanel({
  phase,
  source,
  blockSource,
  reputation,
  spamhaus,
}: {
  phase: Phase;
  source?: SourceMeta;
  blockSource?: SourceMeta;
  reputation: Reputation | null;
  spamhaus: { listed: boolean; status: string; codes: string[]; detail?: string } | null;
}) {
  const total = reputation
    ? reputation.malicious + reputation.suspicious + reputation.harmless + reputation.undetected
    : 0;
  const width = (n: number) => (total ? `${Math.max(0, (n / total) * 100)}%` : "0%");
  return (
    <Section id="reputation" title="Reputation" defaultOpen={false}>
      <div className="grid gap-5">
        <FeedSlot phase={phase} source={source}>
          {reputation ? (
            <div className="grid gap-3">
              <div className="flex h-2 overflow-hidden rounded-full bg-raised">
                <span className="bg-critical" style={{ width: width(reputation.malicious) }} />
                <span className="bg-warn" style={{ width: width(reputation.suspicious) }} />
                <span className="bg-ok" style={{ width: width(reputation.harmless) }} />
                <span className="bg-line" style={{ width: width(reputation.undetected) }} />
              </div>
              <dl className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                <Meta label="Malicious" value={reputation.malicious} />
                <Meta label="Suspicious" value={reputation.suspicious} />
                <Meta label="Harmless" value={reputation.harmless} />
                <Meta label="Undetected" value={reputation.undetected} />
                <Meta label="VT reputation" value={reputation.reputation} />
                <Meta label="Last analysis" value={reputation.lastAnalysis ? formatWhen(reputation.lastAnalysis) : undefined} />
              </dl>
              {reputation.engines.length ? (
                <ul className="grid gap-1">
                  {reputation.engines.map((engine) => (
                    <li key={engine.name} className="flex items-baseline justify-between gap-3 font-mono text-xs">
                      <span className="text-fg">{engine.name}</span>
                      <span className={engine.category === "malicious" ? "text-critical" : "text-warn"}>
                        {engine.result || engine.category}
                      </span>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-sm text-muted">No malicious or suspicious engine names in the report.</p>
              )}
            </div>
          ) : (
            <p className="text-sm text-muted">VirusTotal returned no engine report.</p>
          )}
        </FeedSlot>
        <div className="border-t border-line pt-4">
          <p className="mb-2 text-xs text-faint">Spamhaus ZEN {blockSource ? `· ${sourceWord(blockSource)}` : ""}</p>
          {spamhaus ? (
            <p className={`text-sm ${spamhaus.listed ? "text-critical" : "text-fg"}`}>
              {spamhaus.listed
                ? `Listed (${spamhaus.codes.join(", ")})`
                : spamhaus.status === "clean"
                  ? "Not listed."
                  : spamhaus.detail || "Lookup unavailable."}
            </p>
          ) : (
            <p className="text-sm text-muted">{blockSource?.detail ?? "Waiting on the DNSBL."}</p>
          )}
        </div>
      </div>
    </Section>
  );
}

export function ThreatPanel({
  phase,
  abuseSource,
  noiseSource,
  mdtiSource,
  abuse,
  greynoise,
  mdti,
}: {
  phase: Phase;
  abuseSource?: SourceMeta;
  noiseSource?: SourceMeta;
  mdtiSource?: SourceMeta;
  abuse: { score: number; totalReports: number; distinctReporters?: number; lastReportedAt?: string; usageType?: string; isp?: string; domain?: string; categories: { name: string; count: number }[]; recent: { reportedAt?: string; comment?: string; categories: string[] }[] } | null;
  greynoise: GreyNoise | null;
  mdti: { classification?: string; score: number | null; rules: { name: string; description?: string; severity?: string; url?: string }[]; firstSeen?: string; lastSeen?: string } | null;
}) {
  return (
    <Section id="threats" title="Threat intelligence" defaultOpen={false}>
      <div className="grid gap-5">
        <div>
          <h3 className="mb-2 text-sm font-medium">AbuseIPDB</h3>
          <FeedSlot phase={phase} source={abuseSource}>
            {abuse ? (
              <div className="grid gap-3">
                <dl className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                  <Meta label="Confidence" value={abuse.score} />
                  <Meta label="Reports" value={abuse.totalReports} />
                  <Meta label="Reporters" value={abuse.distinctReporters} />
                  <Meta label="Last report" value={abuse.lastReportedAt ? formatWhen(abuse.lastReportedAt) : undefined} />
                  <Meta label="Usage" value={abuse.usageType} />
                  <Meta label="ISP" value={abuse.isp} />
                  <Meta label="Domain" value={abuse.domain} />
                </dl>
                {abuse.categories.length ? (
                  <ul className="flex flex-wrap gap-1.5">
                    {abuse.categories.map((category) => (
                      <li key={category.name} className="rounded-sm bg-warn-dim px-2 py-0.5 font-mono text-xs text-warn">
                        {category.name} {category.count}
                      </li>
                    ))}
                  </ul>
                ) : null}
                {abuse.recent.length ? (
                  <ul className="grid gap-2">
                    {abuse.recent.map((report, index) => (
                      <li key={`${report.reportedAt ?? "r"}-${index}`} className="text-sm text-muted">
                        <span className="font-mono text-xs text-faint">{report.reportedAt ? formatWhen(report.reportedAt) : "Undated"}</span>
                        {report.categories.length ? ` · ${report.categories.join(", ")}` : ""}
                        {report.comment ? <span className="block text-fg">{report.comment}</span> : null}
                      </li>
                    ))}
                  </ul>
                ) : null}
              </div>
            ) : (
              <p className="text-sm text-muted">No AbuseIPDB record.</p>
            )}
          </FeedSlot>
        </div>
        <div className="border-t border-line pt-4">
          <h3 className="mb-2 text-sm font-medium">GreyNoise</h3>
          <FeedSlot phase={phase} source={noiseSource}>
            {greynoise ? (
              <div className="grid gap-3">
                <dl className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                  <Meta label="Classification" value={greynoise.classification} />
                  <Meta label="Noise" value={greynoise.noise} />
                  <Meta label="Known service" value={greynoise.riot} />
                  <Meta label="Actor" value={greynoise.actor} />
                  <Meta label="Name" value={greynoise.name} />
                  <Meta label="Last seen" value={greynoise.lastSeen} />
                </dl>
                {greynoise.message ? <p className="text-sm text-muted">{greynoise.message}</p> : null}
                {greynoise.tags.length ? (
                  <ul className="flex flex-wrap gap-1.5">
                    {greynoise.tags.map((tag) => (
                      <li key={tag} className="rounded-sm bg-raised px-2 py-0.5 font-mono text-xs text-muted">
                        {tag}
                      </li>
                    ))}
                  </ul>
                ) : null}
                {greynoise.link ? (
                  <a href={greynoise.link} target="_blank" rel="noreferrer" className="text-sm text-accent underline-offset-2 hover:underline">
                    Open in GreyNoise
                  </a>
                ) : null}
              </div>
            ) : (
              <p className="text-sm text-muted">No GreyNoise classification.</p>
            )}
          </FeedSlot>
        </div>
        <div className="border-t border-line pt-4">
          <h3 className="mb-2 text-sm font-medium">Microsoft Defender Threat Intelligence</h3>
          <FeedSlot phase={phase} source={mdtiSource}>
            {mdti ? (
              <div className="grid gap-3">
                <dl className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                  <Meta label="Classification" value={mdti.classification} />
                  <Meta label="Score" value={mdti.score} />
                  <Meta label="First seen" value={mdti.firstSeen ? formatWhen(mdti.firstSeen) : undefined} />
                  <Meta label="Last seen" value={mdti.lastSeen ? formatWhen(mdti.lastSeen) : undefined} />
                </dl>
                {mdti.rules.length ? (
                  <ul className="grid gap-2">
                    {mdti.rules.map((rule) => (
                      <li key={rule.name} className="text-sm">
                        <p className="font-medium text-fg">
                          {rule.name}
                          {rule.severity ? <span className="ml-2 font-mono text-xs text-warn">{rule.severity}</span> : null}
                        </p>
                        {rule.description ? <p className="text-pretty text-muted">{rule.description}</p> : null}
                        {rule.url ? (
                          <a href={rule.url} target="_blank" rel="noreferrer" className="text-accent underline-offset-2 hover:underline">
                            Related article
                          </a>
                        ) : null}
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-sm text-muted">No campaign rules on this host.</p>
                )}
              </div>
            ) : (
              <p className="text-sm text-muted">No Defender TI host record.</p>
            )}
          </FeedSlot>
        </div>
      </div>
    </Section>
  );
}

export function ShodanPanel({
  phase,
  source,
  shodan,
}: {
  phase: Phase;
  source?: SourceMeta;
  shodan: Shodan | null;
}) {
  return (
    <Section id="shodan" title="Shodan" source={source} defaultOpen={false}>
      <FeedSlot phase={phase} source={source} empty="No open services in InternetDB.">
        {shodan ? (
          <div className="grid gap-4">
            <dl className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              <Meta label="Honeypot" value={shodan.honeypot} />
              <Meta label="Honey score" value={shodan.honeyScore} />
              <Meta label="Operating system" value={shodan.os} />
              <Meta label="Organization" value={shodan.org} />
              <Meta label="CVEs" value={shodan.vulnCount} />
              <Meta label="Updated" value={shodan.lastUpdate} />
              <Meta label="Fingerprint" value={shodan.fingerprint} />
            </dl>
            {shodan.ports.length ? (
              <ul className="flex flex-wrap gap-1.5">
                {shodan.ports.map((port) => (
                  <li
                    key={port}
                    className={`rounded-sm px-2 py-0.5 font-mono text-xs ${RISKY.has(port) ? "bg-warn-dim text-warn" : "bg-raised text-muted"}`}
                  >
                    {port}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-muted">No open ports recorded.</p>
            )}
            {shodan.vulns.length ? (
              <ul className="flex flex-wrap gap-1.5">
                {shodan.vulns.map((cve) => (
                  <li key={cve} className="rounded-sm bg-critical-dim px-2 py-0.5 font-mono text-xs text-critical">
                    {cve}
                  </li>
                ))}
              </ul>
            ) : null}
            {shodan.cpes.length ? (
              <ul className="grid gap-1 font-mono text-xs text-muted">
                {shodan.cpes.map((cpe) => (
                  <li key={cpe} className="break-all">{cpe}</li>
                ))}
              </ul>
            ) : null}
            {shodan.services.length ? (
              <div className="grid gap-2">
                {shodan.services.map((service) => (
                  <details key={`${service.port}-${service.transport ?? "tcp"}`} className="rounded-md bg-bg px-3 py-2">
                    <summary className="cursor-pointer font-mono text-sm text-fg">
                      {service.port}/{service.transport ?? "tcp"}
                      {service.product ? ` · ${service.product}${service.version ? ` ${service.version}` : ""}` : ""}
                    </summary>
                    {service.banner ? (
                      <pre className="mt-2 overflow-x-auto font-mono text-xs leading-relaxed whitespace-pre-wrap text-muted">
                        {service.banner}
                      </pre>
                    ) : (
                      <p className="mt-2 text-sm text-faint">No banner captured.</p>
                    )}
                  </details>
                ))}
              </div>
            ) : null}
          </div>
        ) : (
          <p className="text-sm text-muted">No fingerprint.</p>
        )}
      </FeedSlot>
    </Section>
  );
}

export function DnsPanel({
  phase,
  source,
  whois,
  passiveDns,
  timeline,
}: {
  phase: Phase;
  source?: SourceMeta;
  whois: Whois | null;
  passiveDns: PassiveDns[];
  timeline: TimelineEvent[];
}) {
  return (
    <Section id="dns" title="DNS and RDAP" source={source} defaultOpen={false}>
      <FeedSlot phase={phase} source={source}>
        {whois ? (
          <div className="grid gap-4">
            <dl className="grid grid-cols-2 gap-3 sm:grid-cols-3">
              <Meta label="Registry" value={whois.registry} />
              <Meta label="Registrar" value={whois.registrar} />
              <Meta label="Provider" value={whois.provider} />
              <Meta label="Net name" value={whois.name} />
              <Meta label="Handle" value={whois.handle} />
              <Meta label="CIDR" value={whois.cidr} />
              <Meta label="Range" value={whois.range} />
              <Meta label="Registered" value={whois.registered ? formatWhen(whois.registered) : undefined} />
              <Meta label="Updated" value={whois.updated ? formatWhen(whois.updated) : undefined} />
            </dl>
            {whois.abuseEmails.length ? (
              <div>
                <p className="text-xs text-faint">Abuse contacts</p>
                <ul className="mt-1 grid gap-1">
                  {whois.abuseEmails.map((email) => (
                    <li key={email}>
                      <a href={`mailto:${email}`} className="font-mono text-sm text-accent underline-offset-2 hover:underline">
                        {email}
                      </a>
                    </li>
                  ))}
                  {whois.abusePhones.map((phone) => (
                    <li key={phone} className="font-mono text-sm text-fg">{phone}</li>
                  ))}
                </ul>
              </div>
            ) : (
              <p className="text-sm text-muted">No abuse contact in the RDAP record.</p>
            )}
            {whois.excerpt ? <p className="text-sm text-pretty text-muted">{whois.excerpt}</p> : null}
          </div>
        ) : (
          <p className="text-sm text-muted">No RDAP record yet.</p>
        )}
      </FeedSlot>
      <div className="mt-4 border-t border-line pt-4">
        <h3 className="mb-2 text-sm font-medium">Hostnames</h3>
        {passiveDns.length ? (
          <ul className="grid gap-1">
            {passiveDns.map((row) => (
              <li key={`${row.source}-${row.hostname}`} className="flex flex-wrap items-baseline justify-between gap-2 font-mono text-xs">
                <span className="break-all text-fg">{row.hostname}</span>
                <span className="text-faint">{row.source}{row.lastSeen ? ` · ${formatWhen(row.lastSeen)}` : ""}</span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-muted">
            {phase === "running" ? "Hostnames arrive as ipinfo, Shodan, VirusTotal, and OTX return." : "No hostnames collected."}
          </p>
        )}
      </div>
      {timeline.length ? (
        <div className="mt-4 border-t border-line pt-4">
          <h3 className="mb-2 text-sm font-medium">Timeline</h3>
          <ol className="grid gap-2">
            {timeline.map((event) => (
              <li key={`${event.source}-${event.label}-${event.at}`} className="flex flex-wrap gap-2 text-sm">
                <span className="font-mono text-xs text-faint">{event.at ? formatWhen(event.at) : "Undated"}</span>
                <span className="text-fg">{event.label}</span>
                <span className="text-muted">{event.source}</span>
              </li>
            ))}
          </ol>
        </div>
      ) : null}
    </Section>
  );
}

export function IocPanel({
  phase,
  source,
  otx,
}: {
  phase: Phase;
  source?: SourceMeta;
  otx: {
    pulseCount: number;
    pulses: { name: string; tags: string[]; adversary?: string; malwareFamilies: string[]; modified?: string }[];
    malwareFamilies: string[];
    adversaries: string[];
    samples: { hash: string; date?: string }[];
  } | null;
}) {
  return (
    <Section id="ioc" title="OTX" source={source} defaultOpen={false}>
      <FeedSlot phase={phase} source={source}>
        {otx ? (
          <div className="grid gap-4">
            <dl className="grid grid-cols-2 gap-3 sm:grid-cols-3">
              <Meta label="Pulses" value={otx.pulseCount} />
              <Meta label="Malware families" value={otx.malwareFamilies.join(", ")} />
              <Meta label="Adversaries" value={otx.adversaries.join(", ")} />
            </dl>
            {otx.pulses.length ? (
              <ul className="grid gap-3">
                {otx.pulses.map((pulse) => (
                  <li key={pulse.name} className="border-l-2 border-line pl-3">
                    <p className="text-sm font-medium text-fg">{pulse.name}</p>
                    <p className="text-xs text-faint">
                      {[pulse.adversary, pulse.modified ? formatWhen(pulse.modified) : ""].filter(Boolean).join(" · ")}
                    </p>
                    {pulse.malwareFamilies.length ? (
                      <p className="text-sm text-warn">{pulse.malwareFamilies.join(", ")}</p>
                    ) : null}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-muted">No pulses associated with this indicator.</p>
            )}
            {otx.samples.length ? (
              <div>
                <p className="text-xs text-faint">Related malware samples</p>
                <ul className="mt-1 grid gap-1 font-mono text-xs text-muted">
                  {otx.samples.map((sample) => (
                    <li key={sample.hash} className="break-all">{sample.hash}</li>
                  ))}
                </ul>
              </div>
            ) : null}
          </div>
        ) : (
          <p className="text-sm text-muted">No OTX record.</p>
        )}
      </FeedSlot>
    </Section>
  );
}

export function SummaryPanel({
  phase,
  summary,
  actions,
  changes,
  previousAt,
  logStatus,
  toolbar,
}: {
  phase: Phase;
  summary: string;
  recommendation: string;
  actions?: string[];
  changes?: string[] | null;
  previousAt?: string;
  verdict?: Verdict;
  logStatus?: "saved" | "unavailable";
  toolbar?: ReactNode;
}) {
  return (
    <Section
      id="summary"
      title="SOC summary"
      info="The note only uses sources that replied. If one did not reply, the note says so. Silence is not a clean result."
      defaultOpen
    >
      {phase === "running" && !summary ? (
        <p className="flex items-center gap-2 text-sm text-muted">
          <span className="inline-block size-4 animate-spin rounded-full border-2 border-line border-t-accent" />
          Writing the summary after every feed returns.
        </p>
      ) : summary ? (
        <div className="grid gap-3">
          {actions?.length ? (
            <div>
              <h3 className="text-sm font-medium">Next five minutes</h3>
              <ul className="mt-2 grid gap-1">
                {actions.map((step) => (
                  <li key={step} className="text-sm text-pretty text-fg">
                    {step}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
          {changes === null ? (
            <p className="text-sm text-muted">First lookup of this address.</p>
          ) : changes?.length ? (
            <div>
              <h3 className="text-sm font-medium">Since last lookup{previousAt ? ` · ${formatWhen(previousAt)}` : ""}</h3>
              <ul className="mt-2 grid gap-1">
                {changes.map((line) => (
                  <li key={line} className="text-sm text-pretty text-fg">
                    {line}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
          {summary.trim() ? <p className="text-sm text-pretty text-fg">{summary.trim()}</p> : null}
          {logStatus === "unavailable" ? (
            <p className="text-xs text-warn">This lookup could not be written to the workspace log.</p>
          ) : null}
        </div>
      ) : (
        <p className="text-sm text-muted">The summary is generated from the feeds that actually answered. Nothing is filled in ahead of a lookup.</p>
      )}
      {toolbar ? <div className="mt-3 flex flex-wrap gap-2 border-t border-line pt-3">{toolbar}</div> : null}
    </Section>
  );
}

export function RawPanel({ value }: { value: unknown }) {
  return (
    <Section id="raw" title="Raw JSON" defaultOpen={false}>
      {value ? <JsonView value={value} /> : <p className="text-sm text-muted">The unified record appears here after a lookup.</p>}
    </Section>
  );
}

function plainVerdict(verdict: Verdict | undefined, phase: Phase): string {
  if (verdict === "unknown") return "We don't have enough answers to call this safe.";
  if (verdict === "suspicious") return "Look at this before you allow it or block it.";
  if (verdict === "critical") return "This looks serious. Pass it on.";
  if (verdict === "benign") return "One source saw nothing bad. Silence from the others is not a promise.";
  if (phase === "running") return "Still asking the sources.";
  return "Paste a public IP to start.";
}

function scoreTip(verdict: Verdict | undefined, phase: Phase): string {
  const scale = "The number only adds up what you see below. It is not a score from one company.";
  if (verdict === "unknown") return `We did not get enough to call this safe. Unknown is not the same as clean. ${scale}`;
  if (verdict === "benign") return `One source said it saw nothing bad. The others may not have answered. ${scale}`;
  if (verdict === "suspicious") return `Look at this before you allow it or block it. ${scale}`;
  if (verdict === "critical") return `The sources point to serious trouble. The note says to pass this on. ${scale}`;
  if (phase === "running") return `The number is still coming in. ${scale}`;
  return scale;
}

function formatWhen(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString(undefined, { month: "short", day: "numeric", year: "numeric" });
}

export function sourceById(sources: SourceMeta[], id: SourceMeta["id"]): SourceMeta | undefined {
  return sources.find((source) => source.id === id);
}
