import type {
  Abuse,
  Asn,
  Finding,
  Geo,
  GreyNoise,
  Mdti,
  Otx,
  PassiveDns,
  Reputation,
  Shodan,
  SourceMeta,
  Spamhaus,
  TimelineEvent,
  Verdict,
  Whois,
} from "./types";
import { unique } from "./read.ts";

const RISKY: Record<number, string> = {
  21: "FTP",
  22: "SSH",
  23: "Telnet",
  25: "SMTP",
  445: "SMB",
  1433: "MSSQL",
  2375: "Docker",
  3306: "MySQL",
  3389: "RDP",
  5432: "Postgres",
  5900: "VNC",
  6379: "Redis",
  9200: "Elasticsearch",
  11211: "Memcached",
  27017: "MongoDB",
  31337: "backdoor",
};

export type AssessInput = {
  ip: string;
  version: 4 | 6;
  cgnat: boolean;
  geo?: Geo;
  asn?: Asn;
  reputation?: Reputation | null;
  abuse?: Abuse | null;
  greynoise?: GreyNoise | null;
  shodan?: Shodan | null;
  whois?: Whois | null;
  otx?: Otx | null;
  mdti?: Mdti | null;
  spamhaus?: Spamhaus | null;
  sources: SourceMeta[];
};

export type Assessment = {
  verdict: Verdict;
  score: number;
  findings: Finding[];
  tags: string[];
  summary: string;
  recommendation: string;
  timeline: TimelineEvent[];
  passiveDns: PassiveDns[];
  actions: string[];
};

function joinList(items: string[]): string {
  if (items.length <= 1) return items[0] ?? "";
  if (items.length === 2) return `${items[0]} and ${items[1]}`;
  return `${items.slice(0, -1).join(", ")}, and ${items[items.length - 1]}`;
}

export function assess(input: AssessInput): Assessment {
  const findings: Finding[] = [];
  let risk = 0;
  let relief = 0;
  const clauses: string[] = [];

  const reputation = input.reputation ?? null;
  const abuse = input.abuse ?? null;
  const greynoise = input.greynoise ?? null;
  const shodan = input.shodan ?? null;
  const otx = input.otx ?? null;
  const mdti = input.mdti ?? null;
  const spamhaus = input.spamhaus ?? null;
  const geo = input.geo;
  const asn = input.asn;

  if (input.cgnat) {
    findings.push({
      level: "unknown",
      text: "Many people share this address. A report about it may be about someone else.",
    });
  }
  if (geo?.anycast) {
    findings.push({
      level: "unknown",
      text: "This address is shared by many computers. The city is one of those places, not the only one.",
    });
  }
  if (geo?.tor) {
    risk += 14;
    findings.push({ level: "suspicious", text: "ipinfo classifies this address as Tor.", points: 14 });
    clauses.push("ipinfo flags Tor");
  } else if (geo?.vpn || geo?.proxy) {
    risk += 6;
    const kind = [geo.vpn ? "VPN" : "", geo.proxy ? "proxy" : ""].filter(Boolean).join(" / ");
    findings.push({
      level: "unknown",
      text: `ipinfo anonymization flag: ${kind}${geo.privacyService ? ` (${geo.privacyService})` : ""}.`,
      points: 6,
    });
  } else if (geo?.hosting) {
    findings.push({ level: "unknown", text: "ipinfo marks this network as hosting." });
  }

  if (reputation) {
    const mal = reputation.malicious;
    const sus = reputation.suspicious;
    if (mal >= 5) {
      risk += 42;
      findings.push({
        level: "critical",
        text: `${mal} VirusTotal engines flagged this IP.`,
        points: 42,
      });
      clauses.push(`flagged by ${mal} VirusTotal engines`);
    } else if (mal >= 1) {
      const points = 16 + mal;
      risk += points;
      findings.push({
        level: "suspicious",
        text: `${mal} VirusTotal engine${mal === 1 ? "" : "s"} flagged this IP.`,
        points,
      });
      clauses.push(`flagged by ${mal} VirusTotal engine${mal === 1 ? "" : "s"}`);
    } else if (sus >= 1) {
      risk += 12;
      findings.push({
        level: "suspicious",
        text: `${sus} VirusTotal engine${sus === 1 ? "" : "s"} marked this IP suspicious.`,
        points: 12,
      });
      clauses.push(`marked suspicious by VirusTotal (${sus})`);
    } else if (reputation.harmless + reputation.undetected > 0) {
      relief += 8;
      findings.push({ level: "benign", text: "VirusTotal engines did not flag this IP.", points: -8 });
    }
  }

  if (abuse) {
    if (abuse.score >= 80 || (abuse.score >= 50 && abuse.totalReports >= 10)) {
      risk += 36;
      findings.push({
        level: "critical",
        text: `AbuseIPDB confidence ${abuse.score} from ${abuse.totalReports} reports.`,
        points: 36,
      });
      clauses.push(
        `reported in AbuseIPDB (confidence ${abuse.score}, ${abuse.totalReports} reports)`,
      );
    } else if (abuse.score >= 25 || abuse.totalReports >= 5) {
      risk += 20;
      findings.push({
        level: "suspicious",
        text: `AbuseIPDB confidence ${abuse.score} from ${abuse.totalReports} reports.`,
        points: 20,
      });
      clauses.push(`reported in AbuseIPDB (confidence ${abuse.score})`);
    } else if (abuse.totalReports > 0) {
      risk += 10;
      findings.push({
        level: "suspicious",
        text: `AbuseIPDB has ${abuse.totalReports} low-confidence report${abuse.totalReports === 1 ? "" : "s"}.`,
        points: 10,
      });
      clauses.push(`noted by AbuseIPDB (${abuse.totalReports} reports)`);
    } else {
      relief += 4;
      findings.push({ level: "benign", text: "AbuseIPDB has no reports in the last 90 days.", points: -4 });
    }
  }

  if (greynoise) {
    const classification = greynoise.classification.toLowerCase();
    if (classification === "malicious") {
      risk += 30;
      findings.push({
        level: "critical",
        text: `GreyNoise marks this IP malicious${greynoise.actor ? ` (actor ${greynoise.actor})` : ""}.`,
        points: 30,
      });
      clauses.push("GreyNoise marks it as malicious");
    } else if (greynoise.noise && classification !== "benign") {
      risk += 12;
      findings.push({ level: "suspicious", text: "GreyNoise observes internet scanning from this IP.", points: 12 });
      clauses.push("GreyNoise sees scanning noise");
    } else if (greynoise.riot || classification === "benign") {
      relief += 14;
      const name = greynoise.name ? ` (${greynoise.name})` : "";
      findings.push({ level: "benign", text: `GreyNoise recognizes a known business service${name}.`, points: -14 });
      clauses.push(`GreyNoise lists it as a known service${name}`);
    } else {
      findings.push({
        level: "unknown",
        text:
          greynoise.coverage === "community"
            ? "GreyNoise community has not seen scanning. RIOT (known services) is not in this feed."
            : "GreyNoise has not observed scanning from this IP.",
      });
    }
  }

  if (shodan) {
    const risky = shodan.ports.filter((port) => RISKY[port] !== undefined);
    const names = unique(risky.map((port) => `${RISKY[port]} ${port}`), 6);
    if (names.length) {
      const points = Math.min(18, names.length * 6);
      risk += points;
      findings.push({ level: "suspicious", text: `Exposed ${names.join(", ")}.`, points });
      clauses.push(`Shodan reveals exposed ${names.join(", ")}`);
    }
    if (shodan.honeypot === true) {
      risk += 10;
      findings.push({ level: "suspicious", text: "Shodan honeypot detection is positive.", points: 10 });
      clauses.push("Shodan honeypot detection is positive");
    }
    if (shodan.vulnCount >= 8) {
      risk += 12;
      findings.push({
        level: "suspicious",
        text: `${shodan.vulnCount} known flaws are tied to programs Shodan already saw. That does not mean someone broke in.`,
        points: 12,
      });
      clauses.push(`${shodan.vulnCount} CVEs tied to fingerprinted services`);
    } else if (shodan.vulnCount > 0) {
      findings.push({
        level: "unknown",
        text: `${shodan.vulnCount} known flaw${shodan.vulnCount === 1 ? "" : "s"} are tied to programs Shodan already saw. That does not mean someone broke in.`,
      });
    }
    const shodanMiss = input.sources.find((source) => source.id === "shodan")?.status === "empty";
    if (shodanMiss && !names.length && shodan.ports.length === 0) {
      findings.push({
        level: "unknown",
        text: "Shodan has no record for this IP. That does not mean the ports are closed.",
      });
    } else if (!names.length && shodan.honeypot !== true && shodan.ports.length === 0) {
      findings.push({ level: "benign", text: "No open ports in the Shodan data we retrieved." });
    }
  }

  if (otx) {
    const families = otx.malwareFamilies.slice(0, 3);
    if (otx.pulseCount >= 5 && families.length) {
      risk += 28;
      findings.push({
        level: "critical",
        text: `OTX links this IP to ${otx.pulseCount} pulses and malware ${families.join(", ")}.`,
        points: 28,
      });
      clauses.push(`IOC feeds link it to ${otx.pulseCount} pulses (${families.join(", ")})`);
    } else if (otx.pulseCount >= 1) {
      const points = otx.pulseCount >= 5 ? 22 : 12;
      risk += points;
      findings.push({
        level: "suspicious",
        text: `OTX has ${otx.pulseCount} pulse${otx.pulseCount === 1 ? "" : "s"} for this IP.`,
        points,
      });
      clauses.push(
        `IOC feeds link it to ${otx.pulseCount} pulse${otx.pulseCount === 1 ? "" : "s"}${families.length ? ` (${families.join(", ")})` : ""}`,
      );
    } else {
      findings.push({ level: "benign", text: "AlienVault OTX has no pulses for this IP." });
    }
  }

  if (mdti?.classification) {
    const classification = mdti.classification.toLowerCase();
    if (classification === "malicious") {
      risk += 34;
      findings.push({ level: "critical", text: "Microsoft Defender TI classifies this host as malicious.", points: 34 });
      clauses.push("Microsoft Defender TI context is malicious");
    } else if (classification === "suspicious") {
      risk += 18;
      findings.push({ level: "suspicious", text: "Microsoft Defender TI classifies this host as suspicious.", points: 18 });
      clauses.push("Microsoft Defender TI context is suspicious");
    } else if (classification === "neutral") {
      relief += 8;
      findings.push({ level: "benign", text: "Defender TI classifies it as neutral.", points: -8 });
    }
  }

  if (spamhaus) {
    if (spamhaus.listed) {
      const hard = spamhaus.codes.some((code) => /SBL|XBL|DROP|CSS/.test(code));
      const points = hard ? 30 : 14;
      risk += points;
      findings.push({
        level: hard ? "critical" : "suspicious",
        text: `Spamhaus ZEN lists this address (${spamhaus.codes.join(", ") || "listed"}).`,
        points,
      });
      clauses.push(`Spamhaus lists it${spamhaus.codes.length ? ` (${spamhaus.codes.join(", ")})` : ""}`);
    } else if (spamhaus.status === "clean") {
      relief += 4;
      findings.push({ level: "benign", text: "Not listed on the Spamhaus blocklist. That does not mean the address is safe.", points: -4 });
    }
  }

  const severe = findings.some((finding) => finding.level === "critical" || finding.level === "suspicious");
  if (severe) {
    for (const finding of findings) {
      if (finding.points !== undefined && finding.points < 0) finding.points = undefined;
    }
  }
  let score = severe ? risk : Math.max(0, risk - relief);
  score = Math.max(0, Math.min(100, score));

  const strongClean = findings.some((finding) =>
    /VirusTotal engines did not|AbuseIPDB has no reports|GreyNoise recognizes|Defender TI classifies it as neutral/.test(
      finding.text,
    ),
  );

  let verdict: Verdict;
  if (findings.some((finding) => finding.level === "critical") || score >= 60) verdict = "critical";
  else if (severe || score >= 28) verdict = "suspicious";
  else if (strongClean) verdict = "benign";
  else verdict = "unknown";

  const gaps = input.sources
    .filter((source) => source.status === "no_key" || source.status === "error")
    .map((source) => source.label);

  let recommendation: string;
  if (verdict === "critical") recommendation = "Recommended escalation to L2.";
  else if (verdict === "suspicious") {
    recommendation =
      "Recommended review before allow-listing. Correlate with identity, VPN logs, and the alerting host.";
  } else if (verdict === "benign" && gaps.length) {
    recommendation = `No escalation on the feeds that answered. Confidence is limited until ${joinList(gaps)} respond.`;
  } else if (verdict === "benign") recommendation = "No escalation. Keep standard monitoring.";
  else recommendation = "Do not treat this as clean. Add feed credentials or re-check before closing the alert.";

  const place = [geo?.city, geo?.region, geo?.country].filter(Boolean).join(", ");
  const announced = asn?.asn ? `${asn.asn}${asn.name ? ` ${asn.name}` : ""}` : "";
  if ((verdict === "benign" || verdict === "unknown") && (place || announced)) {
    const where = [place ? `geolocated to ${place}` : "", announced ? `announced by ${announced}` : ""]
      .filter(Boolean)
      .join(", ");
    clauses.push(where);
  }

  const lead =
    verdict === "critical"
      ? "IP shows high malicious activity"
      : verdict === "suspicious"
        ? "IP shows suspicious activity"
        : verdict === "benign"
          ? "IP shows no material malicious activity"
          : "IP does not have enough reputation coverage to score";

  const answered = input.sources.filter(
    (source) => source.status === "ok" || source.status === "empty",
  ).length;
  const coverage =
    input.sources.length > 0 ? `${answered} of ${input.sources.length} feeds answered.` : "";

  const body = clauses.length ? `${lead}: ${clauses.join("; ")}.` : `${lead}.`;
  const limited = input.sources
    .filter((source) => source.status === "rate_limited")
    .map((source) => source.label);
  const limitNote = limited.length
    ? `${joinList(limited)} ${limited.length === 1 ? "was" : "were"} rate limited.`
    : "";

  const summary = [body, coverage, limitNote, recommendation].filter(Boolean).join(" ");

  const tags = unique(
    [
      ...(reputation?.tags ?? []),
      ...(greynoise?.tags ?? []),
      ...(shodan?.tags ?? []),
      ...(otx?.tags ?? []),
      ...(otx?.malwareFamilies ?? []),
      ...(abuse?.categories.map((category) => category.name) ?? []),
      ...(geo?.tor ? ["tor"] : []),
      ...(geo?.vpn ? ["vpn"] : []),
      ...(geo?.proxy ? ["proxy"] : []),
      ...(geo?.hosting ? ["hosting"] : []),
      ...(shodan?.honeypot ? ["honeypot"] : []),
    ],
    18,
  );

  const timeline: TimelineEvent[] = [];
  const push = (at: string | undefined, source: string, label: string) => {
    if (at) timeline.push({ at, source, label });
  };
  push(reputation?.lastAnalysis, "VirusTotal", "Last engine analysis");
  push(abuse?.lastReportedAt, "AbuseIPDB", "Last abuse report");
  push(greynoise?.lastSeen, "GreyNoise", "Last seen");
  push(shodan?.lastUpdate, "Shodan", "Host record updated");
  push(mdti?.lastSeen, "Defender TI", "Last seen");
  push(mdti?.firstSeen, "Defender TI", "First seen");
  push(input.whois?.updated, "WHOIS", "Network record changed");
  push(input.whois?.registered, "WHOIS", "Network registered");
  for (const pulse of otx?.pulses ?? []) {
    push(pulse.modified, "OTX", pulse.name);
  }
  timeline.sort((a, b) => (b.at ?? "").localeCompare(a.at ?? ""));

  const passiveDns: PassiveDns[] = [];
  for (const row of reputation?.resolutions ?? []) {
    passiveDns.push({ hostname: row.hostname, lastSeen: row.lastSeen, source: "VirusTotal" });
  }
  for (const row of otx?.passiveDns ?? []) {
    passiveDns.push({ hostname: row.hostname, lastSeen: row.lastSeen, source: "OTX" });
  }
  for (const hostname of shodan?.hostnames ?? []) {
    passiveDns.push({ hostname, source: "Shodan" });
  }
  if (geo?.hostname) passiveDns.push({ hostname: geo.hostname, source: "ipinfo" });

  const seenHost = new Set<string>();
  const dns = passiveDns.filter((row) => {
    const key = `${row.source}:${row.hostname.toLowerCase()}`;
    if (seenHost.has(key)) return false;
    seenHost.add(key);
    return true;
  });

  return {
    verdict,
    score,
    findings,
    tags,
    summary,
    recommendation,
    timeline: timeline.slice(0, 12),
    passiveDns: dns.slice(0, 16),
    actions: nextSteps(input).slice(0, 4),
  };
}

function nextSteps(input: AssessInput): string[] {
  const steps: string[] = [];
  if (input.cgnat) {
    steps.push("Do not block this address. Many people share it. Look at the session, not the address.");
  }
  if (input.geo?.anycast) {
    steps.push("Do not block this address. Many computers share it. Block the name or the program, not the address.");
  }
  if (input.shodan?.honeypot === true) {
    steps.push("Do not investigate this as a victim. Shodan marks it as a honeypot.");
  }
  const risky = (input.shodan?.ports ?? []).some((port) => RISKY[port] !== undefined);
  if (risky) {
    steps.push("Check whether the open management port is an approved scanner or jump host before you block it.");
  }
  if (input.spamhaus?.listed) {
    const hard = input.spamhaus.codes.some((code) => /SBL|XBL|DROP|CSS/.test(code));
    steps.push(
      hard
        ? "Confirm the Spamhaus listing, then escalate. SBL, XBL, DROP, and CSS are stronger than a policy listing."
        : "Confirm the Spamhaus code before a block. A policy listing is not a malware listing.",
    );
  }
  if ((input.abuse?.totalReports ?? 0) > 0) {
    steps.push("Correlate AbuseIPDB report times with VPN, proxy, and the alerting host.");
  }
  if (input.geo?.tor || input.geo?.vpn || input.geo?.proxy) {
    steps.push("Treat the anonymization flag as context, not proof. Check whether that egress was expected.");
  }
  return steps;
}
