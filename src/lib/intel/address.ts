import { BlockList, isIP } from "node:net";

const blocked = new BlockList();
blocked.addSubnet("0.0.0.0", 8, "ipv4");
blocked.addSubnet("10.0.0.0", 8, "ipv4");
blocked.addSubnet("127.0.0.0", 8, "ipv4");
blocked.addSubnet("169.254.0.0", 16, "ipv4");
blocked.addSubnet("172.16.0.0", 12, "ipv4");
blocked.addSubnet("192.0.2.0", 24, "ipv4");
blocked.addSubnet("192.168.0.0", 16, "ipv4");
blocked.addSubnet("198.18.0.0", 15, "ipv4");
blocked.addSubnet("198.51.100.0", 24, "ipv4");
blocked.addSubnet("203.0.113.0", 24, "ipv4");
blocked.addSubnet("224.0.0.0", 4, "ipv4");
blocked.addSubnet("240.0.0.0", 4, "ipv4");
blocked.addAddress("::", "ipv6");
blocked.addAddress("::1", "ipv6");
blocked.addSubnet("fc00::", 7, "ipv6");
blocked.addSubnet("fe80::", 10, "ipv6");
blocked.addSubnet("ff00::", 8, "ipv6");
blocked.addSubnet("2001:db8::", 32, "ipv6");

const cgnat = new BlockList();
cgnat.addSubnet("100.64.0.0", 10, "ipv4");

export type AddressCheck =
  | { ok: true; ip: string; version: 4 | 6; cgnat: boolean }
  | { ok: false; message: string };

function expandGroups(ip: string): string[] | null {
  if (ip.includes(".")) return null;
  const halves = ip.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":").filter(Boolean) : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":").filter(Boolean) : [];
  if (halves.length === 1) {
    if (head.length !== 8) return null;
    return head.map((part) => part.padStart(4, "0").toLowerCase());
  }
  const missing = 8 - head.length - tail.length;
  if (missing < 0) return null;
  return [...head, ...Array(missing).fill("0"), ...tail].map((part) => part.padStart(4, "0").toLowerCase());
}

/** IPv4-mapped IPv6 (`::ffff:8.8.8.8`, `::ffff:808:808`) is the same host as the embedded IPv4. */
function unwrapMappedIpv4(ip: string): string | null {
  const lower = ip.toLowerCase();
  const dotted = lower.match(/^(?:::ffff:|(?:0:){5}ffff:)(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (dotted && isIP(dotted[1]) === 4) return dotted[1];
  const groups = expandGroups(lower);
  if (!groups) return null;
  if (!groups.slice(0, 5).every((part) => part === "0000") || groups[5] !== "ffff") return null;
  const hi = Number.parseInt(groups[6], 16);
  const lo = Number.parseInt(groups[7], 16);
  if (!Number.isInteger(hi) || !Number.isInteger(lo)) return null;
  const v4 = [(hi >> 8) & 255, hi & 255, (lo >> 8) & 255, lo & 255].join(".");
  return isIP(v4) === 4 ? v4 : null;
}

export function classifyAddress(raw: string): AddressCheck {
  const ip = raw.trim();
  if (!ip) return { ok: false, message: "Enter an IPv4 or IPv6 address." };
  const mapped = unwrapMappedIpv4(ip);
  if (mapped) return classifyAddress(mapped);
  if (/[a-z]/i.test(ip) && !ip.includes(":") && !isIP(ip)) {
    return { ok: false, message: "Enter an IP address, not a hostname." };
  }
  const version = isIP(ip);
  if (version !== 4 && version !== 6) {
    return { ok: false, message: "Enter a valid IPv4 or IPv6 address." };
  }
  const family = version === 4 ? "ipv4" : "ipv6";
  if (blocked.check(ip, family)) {
    return {
      ok: false,
      message: "That address is not publicly routable. These feeds only cover global unicast IPs.",
    };
  }
  return { ok: true, ip, version, cgnat: version === 4 && cgnat.check(ip, "ipv4") };
}

export type Extracted =
  | { ok: true; ip: string; version: 4 | 6; cgnat: boolean; fromLine: boolean }
  | { ok: false; message: string };

/** Accept a bare address, or the one public address inside a pasted log line. */
export function extractAddress(raw: string): Extracted {
  const text = raw.trim();
  if (!text) return { ok: false, message: "Enter an IPv4 or IPv6 address." };
  const direct = classifyAddress(text);
  if (direct.ok) return { ...direct, fromLine: false };
  if (!/\s/.test(text)) return direct;

  const found = new Map<string, Extract<Extracted, { ok: true }>>();
  let sawPrivate = false;
  for (const token of text.split(/[^0-9a-fA-F:.]+/)) {
    let candidate = token.replace(/^[.:]+|[.:]+$/g, "");
    const v4port = candidate.match(/^(\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}$/);
    if (v4port) candidate = v4port[1];
    if (!candidate || candidate.length > 45) continue;
    const checked = classifyAddress(candidate);
    if (checked.ok) found.set(checked.ip, { ...checked, fromLine: true });
    else if (checked.message.includes("not publicly routable")) sawPrivate = true;
  }
  const picks = [...found.values()];
  if (picks.length === 1) return picks[0];
  if (picks.length > 1) {
    const list = picks
      .slice(0, 4)
      .map((pick) => pick.ip)
      .join(", ");
    return { ok: false, message: `This line has more than one public IP: ${list}. Submit one address.` };
  }
  if (sawPrivate) {
    return { ok: false, message: "That address is not publicly routable. These feeds only cover global unicast IPs." };
  }
  return { ok: false, message: "No public IP in that text." };
}

function hopIp(value: string | undefined): string | null {
  if (!value) return null;
  const trimmed = value.trim().replace(/^\[|\]$/g, "");
  return isIP(trimmed) ? trimmed : null;
}

/** Prefer the platform hop. The left side of X-Forwarded-For is client-supplied. */
export function clientAddress(headers: Headers): string {
  const vercel = headers.get("x-vercel-forwarded-for");
  if (vercel) {
    const first = hopIp(vercel.split(",")[0]);
    if (first) return first;
  }
  const forwarded = headers.get("x-forwarded-for");
  if (forwarded) {
    const hops = forwarded
      .split(",")
      .map((part) => hopIp(part))
      .filter((part): part is string => part !== null);
    const last = hops[hops.length - 1];
    if (last) return last;
  }
  return hopIp(headers.get("x-real-ip") ?? undefined) ?? "local";
}
