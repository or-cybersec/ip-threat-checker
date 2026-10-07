import type { Dossier } from "./types";

export function compareLookups(previous: Dossier, next: Dossier): string[] {
  const lines: string[] = [];
  if (previous.verdict !== next.verdict) {
    lines.push(`Verdict changed from ${previous.verdict} to ${next.verdict}.`);
  }
  if (Math.abs(previous.score - next.score) >= 10) {
    lines.push(`Score moved from ${previous.score} to ${next.score}.`);
  }

  const beforeList = previous.blocklist?.spamhaus;
  const afterList = next.blocklist?.spamhaus;
  if (beforeList && afterList && beforeList.status !== "unavailable" && afterList.status !== "unavailable") {
    if (!beforeList.listed && afterList.listed) {
      lines.push(`Spamhaus was clean. It is now listed (${afterList.codes.join(", ") || "listed"}).`);
    } else if (beforeList.listed && !afterList.listed) {
      lines.push("Spamhaus listed this address last time. It is not listed now.");
    } else if (beforeList.listed && afterList.listed && beforeList.codes.join() !== afterList.codes.join()) {
      lines.push(`Spamhaus codes changed from ${beforeList.codes.join(", ") || "listed"} to ${afterList.codes.join(", ") || "listed"}.`);
    }
  }

  if (previous.shodan && next.shodan) {
    const before = new Set(previous.shodan.ports);
    const after = new Set(next.shodan.ports);
    const added = [...after].filter((port) => !before.has(port));
    const removed = [...before].filter((port) => !after.has(port));
    if (added.length) lines.push(`Shodan now shows port ${added.join(", ")}.`);
    if (removed.length) lines.push(`Port ${removed.join(", ")} is no longer in the Shodan data.`);
  }

  if (previous.abuse && next.abuse && Math.abs(previous.abuse.score - next.abuse.score) >= 20) {
    lines.push(`AbuseIPDB confidence moved from ${previous.abuse.score} to ${next.abuse.score}.`);
  }
  if (previous.reputation && next.reputation && previous.reputation.malicious !== next.reputation.malicious) {
    lines.push(`VirusTotal malicious engines moved from ${previous.reputation.malicious} to ${next.reputation.malicious}.`);
  }
  const beforeNoise = previous.greynoise?.classification;
  const afterNoise = next.greynoise?.classification;
  if (beforeNoise && afterNoise && beforeNoise !== afterNoise) {
    lines.push(`GreyNoise changed from ${beforeNoise} to ${afterNoise}.`);
  }

  return lines.length ? lines.slice(0, 6) : ["No material change since the last lookup."];
}
