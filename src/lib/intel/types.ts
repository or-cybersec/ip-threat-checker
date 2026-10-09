export type FeedId =
  | "ipinfo"
  | "virustotal"
  | "abuseipdb"
  | "greynoise"
  | "shodan"
  | "whois"
  | "otx"
  | "mdti"
  | "spamhaus";

export type Verdict = "critical" | "suspicious" | "benign" | "unknown";

export type SourceStatus =
  | "ok"
  | "empty"
  | "no_key"
  | "error"
  | "rate_limited"
  | "unsupported";

export type SourceMeta = {
  id: FeedId;
  label: string;
  status: SourceStatus;
  ms: number;
  cached: boolean;
  /** When the cached payload was fetched. Absent on a live response. */
  cachedAt?: string;
  detail?: string;
};

export type FeedKeys = {
  virustotal?: string;
  abuseipdb?: string;
  greynoise?: string;
  shodan?: string;
  ipinfo?: string;
  otx?: string;
  mdtiTenant?: string;
  mdtiClientId?: string;
  mdtiClientSecret?: string;
};

export type Geo = {
  city?: string;
  region?: string;
  country?: string;
  countryCode?: string;
  loc?: string;
  timezone?: string;
  postal?: string;
  hostname?: string;
  anycast?: boolean;
  vpn?: boolean;
  proxy?: boolean;
  tor?: boolean;
  relay?: boolean;
  hosting?: boolean;
  privacyService?: string;
};

export type Asn = {
  asn?: string;
  name?: string;
  route?: string;
  domain?: string;
  type?: string;
};

export type EngineHit = {
  name: string;
  category: string;
  result: string;
};

export type Resolution = {
  hostname: string;
  lastSeen?: string;
};

export type Reputation = {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  timeout: number;
  reputation: number | null;
  tags: string[];
  engines: EngineHit[];
  lastAnalysis?: string;
  votesHarmless?: number;
  votesMalicious?: number;
  resolutions: Resolution[];
};

export type AbuseCategory = { name: string; count: number };

export type AbuseReport = {
  reportedAt?: string;
  comment?: string;
  categories: string[];
};

export type Abuse = {
  score: number;
  totalReports: number;
  distinctReporters?: number;
  lastReportedAt?: string;
  usageType?: string;
  isp?: string;
  domain?: string;
  categories: AbuseCategory[];
  recent: AbuseReport[];
};

export type GreyNoise = {
  noise: boolean | null;
  riot: boolean | null;
  classification: string;
  name?: string;
  actor?: string;
  tags: string[];
  lastSeen?: string;
  link?: string;
  message?: string;
  spoofable?: boolean;
  vpn?: boolean;
  /** Community responses omit RIOT, so a known service can still look unseen. */
  coverage?: "community" | "full";
};

export type ShodanService = {
  port: number;
  transport?: string;
  product?: string;
  version?: string;
  banner?: string;
};

export type Shodan = {
  ports: number[];
  hostnames: string[];
  tags: string[];
  vulns: string[];
  vulnCount: number;
  cpes: string[];
  os?: string;
  org?: string;
  lastUpdate?: string;
  honeypot: boolean | null;
  honeyScore: number | null;
  services: ShodanService[];
  fingerprint?: string;
  provenance: string;
};

export type Whois = {
  registry?: string;
  name?: string;
  handle?: string;
  cidr?: string;
  range?: string;
  country?: string;
  provider?: string;
  registrar?: string;
  abuseEmails: string[];
  abusePhones: string[];
  status: string[];
  registered?: string;
  updated?: string;
  excerpt?: string;
};

export type OtxPulse = {
  name: string;
  tags: string[];
  adversary?: string;
  malwareFamilies: string[];
  modified?: string;
};

export type OtxSample = { hash: string; date?: string };

export type Otx = {
  pulseCount: number;
  pulses: OtxPulse[];
  malwareFamilies: string[];
  adversaries: string[];
  tags: string[];
  passiveDns: Resolution[];
  samples: OtxSample[];
};

export type MdtiRule = {
  name: string;
  description?: string;
  severity?: string;
  url?: string;
};

export type Mdti = {
  classification?: string;
  score: number | null;
  rules: MdtiRule[];
  firstSeen?: string;
  lastSeen?: string;
};

export type Spamhaus = {
  listed: boolean;
  status: "listed" | "clean" | "unavailable";
  codes: string[];
  detail?: string;
};

export type Finding = { level: Verdict; text: string; points?: number };

export type TimelineEvent = { at?: string; source: string; label: string };

export type PassiveDns = { hostname: string; lastSeen?: string; source: string };

export type Dossier = {
  ip: string;
  version: 4 | 6;
  queriedAt: string;
  cached: boolean;
  cgnat: boolean;
  geo: Geo;
  asn: Asn;
  reputation: Reputation | null;
  abuse: Abuse | null;
  greynoise: GreyNoise | null;
  shodan: Shodan | null;
  whois: Whois | null;
  otx: Otx | null;
  mdti: Mdti | null;
  blocklist: { spamhaus: Spamhaus } | null;
  passiveDns: PassiveDns[];
  timeline: TimelineEvent[];
  tags: string[];
  findings: Finding[];
  summary: string;
  recommendation: string;
  actions?: string[];
  /** Null on the first lookup of this IP. Omitted on rows saved before comparison existed. */
  changes?: string[] | null;
  previousAt?: string;
  verdict: Verdict;
  score: number;
  sources: SourceMeta[];
  historyId?: number;
  logStatus: "saved" | "unavailable";
};

export type IntelPatch = {
  geo?: Geo;
  asn?: Asn;
  reputation?: Reputation;
  abuse?: Abuse;
  greynoise?: GreyNoise;
  shodan?: Shodan;
  whois?: Whois;
  otx?: Otx;
  mdti?: Mdti;
  blocklist?: { spamhaus: Spamhaus };
};

export type StreamEvent =
  | { type: "meta"; ip: string; version: 4 | 6; cgnat: boolean; fromLine?: boolean }
  | { type: "fragment"; source: SourceMeta; patch: IntelPatch }
  | { type: "complete"; dossier: Dossier }
  | { type: "fatal"; message: string };

export type HistoryRow = {
  id: number;
  ip: string;
  verdict: Verdict;
  score: number;
  summary: string;
  createdAt: string;
  marked: boolean;
};

export const FEEDS: { id: FeedId; label: string; keyed: boolean }[] = [
  { id: "ipinfo", label: "ipinfo", keyed: false },
  { id: "virustotal", label: "VirusTotal", keyed: true },
  { id: "abuseipdb", label: "AbuseIPDB", keyed: true },
  { id: "greynoise", label: "GreyNoise", keyed: false },
  { id: "shodan", label: "Shodan", keyed: false },
  { id: "whois", label: "WHOIS / RDAP", keyed: false },
  { id: "otx", label: "AlienVault OTX", keyed: true },
  { id: "mdti", label: "Defender TI", keyed: true },
  { id: "spamhaus", label: "Spamhaus", keyed: false },
];
