import assert from "node:assert/strict";
import { test } from "node:test";

import { classifyAddress, clientAddress, extractAddress } from "./address.ts";
import { assess } from "./assess.ts";
import { matchAssets } from "./assets.ts";
import { compareLookups } from "./delta.ts";
import { feedHostAllowed } from "./http.server.ts";
import { resolveKeys } from "./keys.ts";
import type { SourceMeta } from "./types.ts";

const sources = (ids: SourceMeta["id"][], status: SourceMeta["status"] = "ok"): SourceMeta[] =>
  ids.map((id) => ({ id, label: id, status, ms: 10, cached: false }));

test("accepts public addresses and rejects reserved ones", () => {
  assert.equal(classifyAddress("8.8.8.8").ok, true);
  assert.equal(classifyAddress("2001:4860:4860::8888").ok, true);
  assert.equal(classifyAddress("10.1.1.1").ok, false);
  assert.equal(classifyAddress("192.168.0.10").ok, false);
  assert.equal(classifyAddress("127.0.0.1").ok, false);
  assert.equal(classifyAddress("::1").ok, false);
  assert.equal(classifyAddress("not an ip").ok, false);
  const cgnat = classifyAddress("100.64.1.1");
  assert.equal(cgnat.ok && cgnat.cgnat, true);
  const mapped = classifyAddress("::ffff:8.8.8.8");
  assert.equal(mapped.ok && mapped.ip === "8.8.8.8" && mapped.version === 4, true);
  const mappedHex = classifyAddress("::ffff:808:808");
  assert.equal(mappedHex.ok && mappedHex.ip === "8.8.8.8" && mappedHex.version === 4, true);
  const mappedFull = classifyAddress("0:0:0:0:0:ffff:808:808");
  assert.equal(mappedFull.ok && mappedFull.ip === "8.8.8.8", true);
  assert.equal(classifyAddress("::ffff:10.1.1.1").ok, false);
  assert.equal(classifyAddress("::ffff:127.0.0.1").ok, false);
});

test("scores a multi-feed malicious IP as critical and tells the analyst to escalate", () => {
  const result = assess({
    ip: "203.0.113.50",
    version: 4,
    cgnat: false,
    reputation: {
      malicious: 14,
      suspicious: 2,
      harmless: 10,
      undetected: 40,
      timeout: 0,
      reputation: -40,
      tags: ["malware"],
      engines: [],
      resolutions: [],
    },
    abuse: {
      score: 92,
      totalReports: 40,
      categories: [{ name: "Brute-Force", count: 20 }],
      recent: [],
    },
    greynoise: { noise: true, riot: false, classification: "malicious", tags: ["ssh"], actor: "brute" },
    shodan: {
      ports: [22],
      hostnames: [],
      tags: [],
      vulns: [],
      vulnCount: 0,
      cpes: [],
      honeypot: false,
      honeyScore: 0,
      services: [],
      provenance: "Shodan",
    },
    sources: sources(["virustotal", "abuseipdb", "greynoise", "shodan"]),
  });
  assert.equal(result.verdict, "critical");
  assert.ok(result.score >= 60);
  assert.match(result.summary, /high malicious activity/);
  assert.match(result.summary, /Recommended escalation to L2/);
  assert.match(result.summary, /GreyNoise marks it as malicious/);
  assert.match(result.summary, /exposed SSH 22/);
  const points = Object.fromEntries(result.findings.filter((finding) => finding.points).map((finding) => [finding.text, finding.points]));
  assert.equal(points["14 VirusTotal engines flagged this IP."], 42);
  assert.equal(points["AbuseIPDB confidence 92 from 40 reports."], 36);
  assert.equal(points["GreyNoise marks this IP malicious (actor brute)."], 30);
  assert.equal(points["Exposed SSH 22."], 6);
});

test("does not call a quiet public resolver malicious when reputation feeds are clean", () => {
  const result = assess({
    ip: "8.8.8.8",
    version: 4,
    cgnat: false,
    geo: { city: "Mountain View", region: "California", country: "US", anycast: true },
    asn: { asn: "AS15169", name: "Google LLC" },
    greynoise: { noise: false, riot: true, classification: "benign", name: "Google Public DNS", tags: [] },
    shodan: {
      ports: [],
      hostnames: [],
      tags: [],
      vulns: [],
      vulnCount: 0,
      cpes: [],
      honeypot: null,
      honeyScore: null,
      services: [],
      provenance: "InternetDB",
    },
    spamhaus: { listed: false, status: "clean", codes: [] },
    sources: [
      ...sources(["greynoise", "shodan", "spamhaus", "ipinfo", "whois"]),
      ...sources(["virustotal", "abuseipdb", "otx", "mdti"], "no_key"),
    ],
  });
  assert.equal(result.verdict, "benign");
  assert.match(result.summary, /No escalation/);
  assert.match(result.summary, /Confidence is limited/);
  assert.match(result.summary, /AS15169/);
  assert.equal(result.findings.find((finding) => finding.text.includes("known business service"))?.points, -14);
});

test("does not call a quiet record clean when no reputation source cleared it", () => {
  const result = assess({
    ip: "8.8.8.8",
    version: 4,
    cgnat: false,
    geo: { city: "Mountain View", region: "California", country: "US", anycast: true },
    asn: { asn: "AS15169", name: "Google LLC" },
    greynoise: { noise: false, riot: false, classification: "unseen", tags: [], message: "not scanning" },
    shodan: {
      ports: [53, 443],
      hostnames: ["dns.google"],
      tags: [],
      vulns: [],
      vulnCount: 0,
      cpes: [],
      honeypot: null,
      honeyScore: null,
      services: [],
      provenance: "InternetDB",
    },
    spamhaus: { listed: false, status: "clean", codes: [] },
    sources: [...sources(["greynoise", "shodan", "spamhaus"]), ...sources(["virustotal"], "no_key")],
  });
  assert.equal(result.verdict, "unknown");
  assert.match(result.summary, /enough reputation coverage/);
  assert.match(result.recommendation, /Do not treat this as clean/);
  assert.equal(result.findings.find((finding) => finding.text.startsWith("Not listed"))?.points, -4);
  assert.doesNotMatch(result.summary, /escalation to L2/);
});

test("names a rate-limited feed in the summary", () => {
  const result = assess({
    ip: "8.8.8.8",
    version: 4,
    cgnat: false,
    spamhaus: { listed: false, status: "clean", codes: [] },
    sources: [...sources(["spamhaus"]), ...sources(["greynoise"], "rate_limited")],
  });
  assert.match(result.summary, /greynoise was rate limited/);
});

test("flags an exposed management port without inventing malware", () => {
  const result = assess({
    ip: "45.33.32.156",
    version: 4,
    cgnat: false,
    shodan: {
      ports: [22, 80],
      hostnames: ["scanme.nmap.org"],
      tags: [],
      vulns: [],
      vulnCount: 0,
      cpes: [],
      honeypot: null,
      honeyScore: null,
      services: [],
      provenance: "InternetDB",
    },
    spamhaus: { listed: false, status: "clean", codes: [] },
    sources: sources(["shodan", "spamhaus"]),
  });
  assert.equal(result.verdict, "suspicious");
  assert.match(result.summary, /exposed SSH 22/);
  assert.doesNotMatch(result.summary, /Recommended escalation to L2/);
});

test("community GreyNoise does not read an unseen IP as a known resolver", () => {
  const result = assess({
    ip: "8.8.8.8",
    version: 4,
    cgnat: false,
    greynoise: {
      noise: false,
      riot: false,
      classification: "unseen",
      tags: [],
      coverage: "community",
      message: "IP not observed scanning the internet.",
    },
    sources: sources(["greynoise"]),
  });
  const text = result.findings.map((finding) => finding.text).join(" ");
  assert.match(text, /RIOT/);
  assert.doesNotMatch(text, /known business service/);
});

test("a missing Shodan record is not described as closed ports", () => {
  const result = assess({
    ip: "203.0.113.10",
    version: 4,
    cgnat: false,
    shodan: {
      ports: [],
      hostnames: [],
      tags: [],
      vulns: [],
      vulnCount: 0,
      cpes: [],
      honeypot: null,
      honeyScore: null,
      services: [],
      provenance: "Shodan InternetDB",
    },
    sources: sources(["shodan"], "empty"),
  });
  const text = result.findings.map((finding) => finding.text).join(" ");
  assert.match(text, /no record/);
  assert.doesNotMatch(text, /No open ports/);
});

test("pulls the one public address out of a log line", () => {
  const line = extractAddress("sshd from 8.8.8.8:22 via 10.1.1.1");
  assert.equal(line.ok && line.ip, "8.8.8.8");
  assert.equal(line.ok && line.fromLine, true);
  const two = extractAddress("seen 8.8.8.8 and 1.1.1.1");
  assert.equal(two.ok, false);
  const bare = extractAddress("8.8.8.8");
  assert.equal(bare.ok && bare.fromLine, false);
  assert.equal(extractAddress("192.168.1.1").ok, false);
  const port = extractAddress("8.8.8.8:53");
  assert.equal(port.ok && port.ip, "8.8.8.8");
  assert.equal(port.ok && port.fromLine, true);
  const brackets = extractAddress("[2001:4860:4860::8888]:53");
  assert.equal(brackets.ok && brackets.ip, "2001:4860:4860::8888");
  assert.equal(extractAddress("192.168.1.1:53").ok, false);
  assert.equal(extractAddress("example.com").ok, false);
});

test("an owned resolver is a do-not-block note, not a feed verdict", () => {
  const matches = matchAssets("8.8.8.8", "AS15169", [
    { id: 1, kind: "ip", value: "8.8.8.8", note: "our DNS" },
    { id: 2, kind: "asn", value: "AS15169", note: "Google" },
    { id: 3, kind: "cidr", value: "1.1.1.0/24", note: "cloudflare" },
  ]);
  assert.deepEqual(matches.map((asset) => asset.note), ["our DNS", "Google"]);
});

test("a later lookup reports a new Spamhaus listing", () => {
  const previous = {
    verdict: "unknown",
    score: 0,
    blocklist: { spamhaus: { listed: false, status: "clean", codes: [] } },
    shodan: null,
    abuse: null,
    reputation: null,
    greynoise: null,
  } as unknown as Parameters<typeof compareLookups>[0];
  const next = {
    ...previous,
    verdict: "suspicious",
    score: 30,
    blocklist: { spamhaus: { listed: true, status: "listed", codes: ["XBL"] } },
  } as unknown as Parameters<typeof compareLookups>[0];
  const lines = compareLookups(previous, next).join(" ");
  assert.match(lines, /unknown to suspicious/);
  assert.match(lines, /XBL/);
});

test("anycast gets a do-not-block step", () => {
  const result = assess({
    ip: "8.8.8.8",
    version: 4,
    cgnat: false,
    geo: { anycast: true },
    sources: sources(["ipinfo"]),
  });
  assert.match(result.actions.join(" "), /Do not block this address/);
});

test("rate limit uses the proxy hop, not a spoofed left-most address", () => {
  const headers = new Headers();
  headers.set("x-forwarded-for", "1.2.3.4, 8.8.8.8");
  assert.equal(clientAddress(headers), "8.8.8.8");
  headers.set("x-vercel-forwarded-for", "9.9.9.9, 1.1.1.1");
  assert.equal(clientAddress(headers), "9.9.9.9");
  headers.delete("x-vercel-forwarded-for");
  headers.set("x-forwarded-for", "not-an-ip, 203.0.113.9");
  assert.equal(clientAddress(headers), "203.0.113.9");
});

test("feed redirects stay on known hosts", () => {
  assert.equal(feedHostAllowed("rdap.arin.net"), true);
  assert.equal(feedHostAllowed("ipinfo.io"), true);
  assert.equal(feedHostAllowed("169.254.169.254"), false);
  assert.equal(feedHostAllowed("ipinfo.io.evil.com"), false);
  assert.equal(feedHostAllowed("localhost"), false);
});

test("workspace keys are opt-in and never override a browser key", () => {
  const previous = process.env.VIRUSTOTAL_API_KEY;
  process.env.VIRUSTOTAL_API_KEY = "server-secret";
  try {
    assert.equal(resolveKeys({}, false).virustotal, undefined);
    assert.equal(resolveKeys({}, true).virustotal, "server-secret");
    assert.equal(resolveKeys({ virustotal: "browser" }, true).virustotal, "browser");
  } finally {
    if (previous === undefined) delete process.env.VIRUSTOTAL_API_KEY;
    else process.env.VIRUSTOTAL_API_KEY = previous;
  }
});
