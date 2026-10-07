export type AssetKind = "ip" | "cidr" | "asn";

export type Asset = {
  id: number;
  kind: AssetKind;
  value: string;
  note: string;
};

export function normalizeAsn(value: string): string | null {
  const match = value.trim().toUpperCase().match(/^(?:AS)?(\d{1,10})$/);
  if (!match) return null;
  const number = Number(match[1]);
  if (!Number.isInteger(number) || number <= 0 || number > 4_294_967_295) return null;
  return `AS${number}`;
}

export function ipv4InCidr(ip: string, cidr: string): boolean {
  const match = cidr.match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/);
  if (!match) return false;
  const prefix = Number(match[2]);
  if (prefix < 8 || prefix > 32) return false;
  const ipNum = ipv4ToNumber(ip);
  const base = ipv4ToNumber(match[1]);
  if (ipNum === null || base === null) return false;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (ipNum & mask) === (base & mask);
}

export function matchAssets(ip: string, asn: string | undefined, assets: Asset[]): Asset[] {
  const announced = asn ? normalizeAsn(asn) : null;
  return assets.filter((asset) => {
    if (asset.kind === "ip") return asset.value === ip;
    if (asset.kind === "asn") return announced !== null && asset.value === announced;
    return asset.kind === "cidr" && ipv4InCidr(ip, asset.value);
  });
}

export function assetLine(matches: Asset[], verdict?: string): string | null {
  if (!matches.length) return null;
  const notes = matches.map((asset) => asset.note).join("; ");
  if (verdict === "critical" || verdict === "suspicious") {
    return `On your list (${notes}). Feeds still say ${verdict}. Do not auto-close.`;
  }
  return `On your list: ${notes}. Do not block.`;
}

function ipv4ToNumber(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    value = (value * 256 + octet) >>> 0;
  }
  return value >>> 0;
}
