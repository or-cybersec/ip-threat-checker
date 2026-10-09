import { useState, type ReactNode } from "react";
import { createPortal } from "react-dom";

import { useSettings } from "@/components/intel/settings";

const TERMS: Record<string, string> = {
  "IP address": "The number of a computer on the internet. This page checks that number. It does not scan the computer.",
  Overview: "The short picture: score, place, and the main findings.",
  Summary: "A note you can copy into a ticket.",
  Reputation: "How other security tools have judged this address.",
  Threats: "Reports of attacks, scanners, and campaigns tied to this address.",
  "Threat intelligence": "Reports from other teams about attacks and campaigns. It is not a scan.",
  Shodan: "A public catalog of services seen on this address. It is their old record, not a scan we just ran.",
  DNS: "Names that have pointed at this address, and who registered the network.",
  "DNS and RDAP": "DNS is the name. RDAP is the registration card: who owns the network and whom to mail about abuse.",
  OTX: "A shared list of suspicious addresses and attack names. OTX means Open Threat Exchange.",
  JSON: "The same result, written as data. Useful when you want the full record, not the summary.",
  "Raw JSON": "The same result, written as data. Useful when you want the full record, not the summary.",
  "SOC summary": "A short note for a ticket. It uses only sources that answered. Silence is not a clean result.",
  Hostname: "A name that points at this address, like scanme.nmap.org.",
  Coordinates: "An approximate point for this network. Not where a person is.",
  Timezone: "The clock used for that approximate place.",
  Network: "The block of addresses this one belongs to.",
  VPN: "Yes means a service that hides a person's real address. The city shown is the VPN's city.",
  Proxy: "Yes means a middle computer that sends traffic for someone else.",
  Tor: "Yes means this address is on Tor, a network used to hide where traffic comes from.",
  Hosting: "Yes means a data center or cloud network, not a typical home connection.",
  Malicious: "Security tools that say this address is bad.",
  Suspicious: "Security tools that are unsure, but not comfortable.",
  Harmless: "Security tools that saw nothing bad.",
  Undetected: "Security tools that had no opinion.",
  "VT reputation": "VirusTotal's community score. A negative number means more votes called it bad. It is not the count of antivirus tools.",
  "Last analysis": "When VirusTotal last asked its tools about this address.",
  Confidence: "AbuseIPDB's own certainty, from 0 to 100. It is not a count of reports.",
  Reports: "How many times people reported this address to AbuseIPDB.",
  Reporters: "How many different people sent those reports.",
  "Last report": "When someone last reported this address.",
  Usage: "What kind of network this is, such as a data center or a home provider.",
  ISP: "The company that provides this internet connection.",
  Domain: "A website name tied to this network.",
  Classification: "The label that a source chose, such as malicious, benign, or unknown.",
  Noise: "Yes means GreyNoise has seen background scanning from this address. That is not the same as a targeted attack.",
  "Known service": "Yes means a well-known service, such as a public DNS. GreyNoise calls that RIOT.",
  Actor: "A name for the group or tool behind the traffic, if a source recognized one.",
  Name: "The name GreyNoise uses when it recognizes the service.",
  "Last seen": "When this source last noticed the address.",
  "First seen": "When this source first noticed the address.",
  Score: "A number from that source. It is not the same as this page's score.",
  "This page's score": "A number from 0 to 100 made by the rules on this page. It is not VirusTotal's score and not AbuseIPDB's confidence.",
  Honeypot: "Yes means Shodan thinks this is a trap. Do not treat it as a victim.",
  "Honey score": "From 0 to 1. At 0.5 or more we call it a trap. A trap is bait, not a real server.",
  "Operating system": "The system Shodan thinks is running. It can be wrong.",
  Organization: "The company Shodan associates with this address.",
  CVEs: "Known flaws in programs Shodan saw. A flaw on the list is not proof that someone broke in.",
  Updated: "When this record was last refreshed by that source.",
  Fingerprint: "A short description of the software Shodan recognized.",
  Registry: "The regional office that handed out this block of addresses.",
  Registrar: "The company that registered the name, if this record has one.",
  Provider: "The network operator who has this address.",
  "Net name": "The label on this block of addresses in the registry.",
  Handle: "The registry's own ID for this record.",
  CIDR: "The size of the address block, written like 45.33.32.0/19. A smaller number after the slash means a bigger block.",
  Range: "The first and last address in this block.",
  Registered: "When this block was first recorded.",
  Pulses: "Collections of clues that mention this address. One pulse is one person's list.",
  "Malware families": "Names of malicious programs linked to this address.",
  Adversaries: "Names of attack groups linked to this address. A link is not proof they are active now.",
  AbuseIPDB: "A list of addresses people have reported for attacks.",
  GreyNoise: "Tells noise (background scanners) apart from traffic that looks targeted.",
  VirusTotal: "Asks many antivirus tools what they think of this address.",
  RDAP: "The registration card for the address: who has the network, and whom to contact about abuse.",
  "Microsoft Defender Threat Intelligence": "Microsoft's notes on addresses tied to attacks and campaigns. It needs a key.",
  "Spamhaus ZEN": "A blocklist of addresses used for spam and attacks. Not listed does not mean the address is safe.",
  Hostnames: "Names that have pointed at this address.",
  Timeline: "Dates the sources reported, newest first.",
  IPv4: "An older, shorter internet address. Four numbers separated by dots.",
  IPv6: "A newer, longer internet address. It uses hex digits and colons.",
  CRITICAL: "At least one serious sign, or a high score. Hand this to someone more senior.",
  SUSPICIOUS: "Something is worth a look before you allow it or block it.",
  BENIGN: "A source that answered saw nothing bad, and nothing serious came back. Silence from the others is not a promise.",
  UNKNOWN: "Nothing here is serious enough to escalate, and nothing is strong enough to call it safe.",
  SCORING: "The score is still being added up.",
  FAILED: "The lookup did not finish.",
  STANDBY: "Nothing has been checked yet.",
  ASN: "The number of the company that runs this network. The city is theirs, not a person's.",
  "Carrier-grade NAT": "Many customers share this address. A report may be about someone else on it.",
  Credentials: "Keys for the sources that require one. They stay in this browser.",
  "Our network": "Addresses you marked as your own. A match says do not block, unless the result is suspicious or critical.",
  "Workspace log": "Lookups kept while this app is running. They are cleared when the app stops.",
  "Google DNS": "A public name server. Useful as a calm example. The verdict still depends on what the sources answer.",
  Cloudflare: "A public name server. Useful as a calm example. The verdict still depends on what the sources answer.",
  Quad9: "A public name server. Useful as a calm example. The verdict still depends on what the sources answer.",
  "scanme.nmap.org": "A public test computer that publishes open ports. It is an example, not a real incident.",
  ipinfo: "Where this network is registered, and whether it looks like a VPN, proxy, or data center.",
  "WHOIS / RDAP": "The registration card for the address: who has the network, and whom to contact about abuse.",
  "AlienVault OTX": "A shared list of suspicious addresses and attack names. OTX means Open Threat Exchange.",
  "Defender TI": "Short for Microsoft Defender Threat Intelligence. It needs a key.",
  Defender: "Short for Microsoft Defender Threat Intelligence. It needs a key.",
  Spamhaus: "A blocklist of addresses used for spam and attacks. Not listed does not mean the address is safe.",
  live: "This source just answered.",
  cached: "This answer is saved from the last ask, up to about ten minutes ago. We did not ask again.",
  "no key": "This source needs a key. We did not ask it.",
  limited: "This source refused for now. The other answers still count.",
  "no hit": "This source answered and had nothing on this address.",
  error: "This source did not answer. That is not a clean result.",
  skipped: "This source does not cover this kind of address.",
  querying: "We are asking this source now.",
  waiting: "This source has not been asked yet.",
  Tag: "A word a source attached. It is their label, not our verdict.",
  "Report category": "The kind of attack people reported, such as scanning or attempts to log in.",
  Port: "A door Shodan has seen open. Visible does not mean someone broke in.",
  "Risky port": "A door often used for remote login or a database. Still not proof of a break-in.",
  CVE: "The ID of a known flaw in a program. Listed does not mean someone used it.",
  CPE: "The name of a program Shodan thinks is running.",
  Points: "How much this line moved the score. A minus lowers it. The score cannot go below zero.",
};

export function Term({
  name,
  children,
  focusable = true,
}: {
  name: string;
  children?: ReactNode;
  focusable?: boolean;
}) {
  const text = TERMS[name];
  const label = children ?? name;
  const { settings } = useSettings();
  const [pos, setPos] = useState<{ x: number; y: number; below: boolean } | null>(null);

  if (!text || !settings.explanations) return <>{label}</>;

  const place = (node: HTMLElement) => {
    const rect = node.getBoundingClientRect();
    const width = 256;
    let x = rect.left;
    if (x + width > window.innerWidth - 8) x = window.innerWidth - width - 8;
    if (x < 8) x = 8;
    const below = rect.top < 80;
    setPos({ x, y: below ? rect.bottom + 6 : rect.top - 6, below });
  };

  return (
    <span
      tabIndex={focusable ? 0 : undefined}
      className="cursor-help underline decoration-dotted decoration-faint/80 underline-offset-4"
      onMouseEnter={(event) => place(event.currentTarget)}
      onMouseLeave={() => setPos(null)}
      onFocus={(event) => {
        if (focusable) place(event.currentTarget);
      }}
      onBlur={() => setPos(null)}
    >
      {label}
      {pos && typeof document !== "undefined"
        ? createPortal(
            <span
              role="tooltip"
              style={{
                position: "fixed",
                left: pos.x,
                top: pos.y,
                transform: pos.below ? undefined : "translateY(-100%)",
              }}
              className="z-50 w-64 rounded-md border border-line bg-bg px-2.5 py-1.5 text-left font-sans text-xs font-normal tracking-normal text-pretty text-fg normal-case"
            >
              {text}
            </span>,
            document.body,
          )
        : null}
    </span>
  );
}

export function statusTerm(status: string | undefined, cached: boolean | undefined, running: boolean): string {
  if (!status) return running ? "querying" : "waiting";
  if (status === "ok") return cached ? "cached" : "live";
  if (status === "empty") return "no hit";
  if (status === "no_key") return "no key";
  if (status === "rate_limited") return "limited";
  if (status === "error") return "error";
  if (status === "unsupported") return "skipped";
  return "waiting";
}
