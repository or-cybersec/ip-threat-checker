import type { Asn, Geo, IntelPatch } from "./types";

function pick<T>(current: T | undefined, next: T | undefined): T | undefined {
  if (typeof current === "boolean") return current;
  if (current !== undefined && current !== null && current !== "") return current;
  if (typeof next === "boolean") return next;
  if (next !== undefined && next !== null && next !== "") return next;
  return undefined;
}

export function mergeGeo(current?: Geo, next?: Geo): Geo | undefined {
  if (!current) return next;
  if (!next) return current;
  return {
    city: pick(current.city, next.city),
    region: pick(current.region, next.region),
    country: pick(current.country, next.country),
    countryCode: pick(current.countryCode, next.countryCode),
    loc: pick(current.loc, next.loc),
    timezone: pick(current.timezone, next.timezone),
    postal: pick(current.postal, next.postal),
    hostname: pick(current.hostname, next.hostname),
    anycast: pick(current.anycast, next.anycast),
    vpn: pick(current.vpn, next.vpn),
    proxy: pick(current.proxy, next.proxy),
    tor: pick(current.tor, next.tor),
    relay: pick(current.relay, next.relay),
    hosting: pick(current.hosting, next.hosting),
    privacyService: pick(current.privacyService, next.privacyService),
  };
}

export function mergeAsn(current?: Asn, next?: Asn): Asn | undefined {
  if (!current) return next;
  if (!next) return current;
  return {
    asn: pick(current.asn, next.asn),
    name: pick(current.name, next.name),
    route: pick(current.route, next.route),
    domain: pick(current.domain, next.domain),
    type: pick(current.type, next.type),
  };
}

export function mergePatch(base: IntelPatch, add: IntelPatch): IntelPatch {
  return {
    geo: mergeGeo(base.geo, add.geo),
    asn: mergeAsn(base.asn, add.asn),
    reputation: add.reputation ?? base.reputation,
    abuse: add.abuse ?? base.abuse,
    greynoise: add.greynoise ?? base.greynoise,
    shodan: add.shodan ?? base.shodan,
    whois: add.whois ?? base.whois,
    otx: add.otx ?? base.otx,
    mdti: add.mdti ?? base.mdti,
    blocklist: add.blocklist ?? base.blocklist,
  };
}
