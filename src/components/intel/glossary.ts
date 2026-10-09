export type GlossaryEntry = {
  term: string;
  text: string;
};

export type GlossaryGroup = {
  title: string;
  entries: GlossaryEntry[];
};

export const GLOSSARY: GlossaryGroup[] = [
  {
    title: "The address",
    entries: [
      {
        term: "IP address",
        text: "A number that identifies a connection on a network. This page checks a public address by asking other services. It does not scan the computer, and it does not tell you who is sitting at it.",
      },
      {
        term: "Public IP",
        text: "An address that can be reached from the internet. Alerts, blocklists, and Shodan are about this kind of address. A home router’s private address, such as 192.168.1.1, is not one of them, and this page refuses it.",
      },
      {
        term: "IPv4",
        text: "The older form of an IP address. Four numbers separated by dots, such as 8.8.8.8. Most abuse reports and many blocklists still speak IPv4 more fluently than IPv6.",
      },
      {
        term: "IPv6",
        text: "The newer, longer form of an IP address. It uses hexadecimal digits and colons. Some sources on this page skip it or know less about it. A skip is not a clean result.",
      },
      {
        term: "DNS",
        text: "The system that turns a name, such as scanme.nmap.org, into an IP address. This page does not run that lookup for you in order to attack anything. It shows names that other services have already tied to the address.",
      },
      {
        term: "Hostname",
        text: "A name that points at an address. One address can have many names, and one name can move to another address. A hostname is a clue, not proof of who operates the machine today.",
      },
      {
        term: "Port",
        text: "A number that marks one service on an address, such as 22 for remote login or 443 for encrypted web pages. Shodan may have seen that door open in the past. An open port is not proof that someone broke in.",
      },
      {
        term: "ASN",
        text: "Autonomous System Number. The number of the organization that announces this block of addresses on the internet. The city next to it is that network’s place, not a person’s.",
      },
      {
        term: "CIDR",
        text: "A way to write a block of addresses, such as 45.33.32.0/19. The number after the slash is how narrowly the block is cut. A smaller number means a larger block.",
      },
      {
        term: "RDAP",
        text: "Registration Data Access Protocol. The current way to read who was given a block of addresses, and which abuse contact to write to. It replaces most of what people used to look up with WHOIS.",
      },
      {
        term: "WHOIS",
        text: "The older registration lookup. This page reads the registration through RDAP and labels that source WHOIS / RDAP. It is the network’s registration card, not a police record.",
      },
      {
        term: "Geolocation",
        text: "An approximate place for the network that holds the address. It often comes from the registry, not from a GPS reading. Do not treat the city as the location of a person.",
      },
      {
        term: "Carrier-grade NAT",
        text: "A provider puts many customers behind one public address. A report on that address may be about a different customer than the one in your alert.",
      },
      {
        term: "VPN",
        text: "A service that hides a user’s real address. The city and the ASN then belong to the VPN company. Yes on this page means the address looks like a VPN exit, not that you have found the user.",
      },
      {
        term: "Proxy",
        text: "A middle computer that forwards traffic for someone else. The address you see can belong to the proxy, not to the person who started the connection.",
      },
      {
        term: "Tor",
        text: "A network designed to hide where traffic comes from. An exit address is shared by many users. A hit on Tor is context, not an identity.",
      },
      {
        term: "Hosting",
        text: "The address belongs to a data center or a cloud network, not to a typical home connection. Cloud addresses are shared and change owners. A report may be about a previous or neighboring customer.",
      },
      {
        term: "Anycast",
        text: "One address is announced from many places at once. Public DNS addresses such as 8.8.8.8, 1.1.1.1, and 9.9.9.9 work this way. Blocking them because they appear in a log usually breaks name resolution for everyone.",
      },
    ],
  },
  {
    title: "The verdict",
    entries: [
      {
        term: "This page's score",
        text: "The number beside the first line, from 0 to 100, made by this page's rules. It is not VirusTotal's score and not AbuseIPDB's confidence. Serious findings add points. A clean finding cannot push it below zero. At 60 or more, or with one serious finding, the verdict is Critical. A warning, or 28 points, makes it Suspicious.",
      },
      {
        term: "Verdict",
        text: "This page’s label for the first look: Critical, Suspicious, Benign, or Unknown. It comes from rules, not from a language model. It is a reason to look, or to stop, not a proof.",
      },
      {
        term: "Critical",
        text: "At least one serious sign, or a high score. Examples are a source calling the address malicious, a hard blocklist hit, or many tied malware notes. Escalate it. The word does not name an attacker.",
      },
      {
        term: "Suspicious",
        text: "Something is worth a look before you allow the address or block it. A few abuse reports, scanning noise, or an exposed management port can be enough. It is not yet a confirmed incident.",
      },
      {
        term: "Benign",
        text: "A source that answered saw a known-good service or an empty abuse report, and nothing serious came back. Sources that stayed silent are not part of that promise.",
      },
      {
        term: "Unknown",
        text: "Nothing in the answers is serious enough to escalate, and nothing is strong enough to call the address safe. Unknown is the honest result when keys are missing. Do not close the alert on Unknown.",
      },
      {
        term: "SOC",
        text: "Security Operations Center. The team that watches alerts and decides what to escalate. The SOC summary on this page is a short note for that work. It uses only sources that answered.",
      },
      {
        term: "Ticket",
        text: "The record of one investigation. Copy for ticket takes the note under the first line, not the raw record.",
      },
      {
        term: "Triage",
        text: "The first sort of an alert: look, escalate, or leave it. This page is a triage aid. It is not the whole investigation.",
      },
      {
        term: "Escalate",
        text: "Hand the case to someone with more context or more authority, often called L2. Critical on this page means escalate. It does not mean you have finished the case.",
      },
      {
        term: "Reputation",
        text: "What other tools and people have said about an address. A bad reputation is a warning. A quiet reputation is not proof that the address is safe.",
      },
      {
        term: "IOC",
        text: "Indicator of compromise. A clue that someone ties to an attack, such as an address, a file hash, or a malware name. A list that mentions your address is a lead. It can be old, copied, or wrong.",
      },
      {
        term: "Threat intelligence",
        text: "Notes from other teams about attacks, tools, and infrastructure. This page reads those notes. It does not produce its own intelligence by scanning.",
      },
      {
        term: "Blocklist",
        text: "A list of addresses that a project advises you to refuse, often because they sent spam or hosted attacks. Being listed is a strong sign. Not being listed does not mean the address is safe.",
      },
      {
        term: "False positive",
        text: "A warning about something that is not actually an attack. Public DNS, scanners that touch the whole internet, and shared cloud addresses cause many of these. This page tries to show that context before you block.",
      },
    ],
  },
  {
    title: "The sources",
    entries: [
      {
        term: "ipinfo",
        text: "Says where the network is registered, which ASN announces it, and whether the address looks like a VPN, a proxy, Tor, or hosting. It does not say if the address is malicious.",
      },
      {
        term: "VirusTotal",
        text: "Asks many security tools what they think of the address, and can show names that once pointed at it. The count of tools is not the same as its community reputation score. This source needs a key. No key means we did not ask.",
      },
      {
        term: "AbuseIPDB",
        text: "Collects reports from people who say an address attacked them. Confidence is their own number from 0 to 100, not a count of reports. Reports can be old or about a shared address. This source needs a key.",
      },
      {
        term: "GreyNoise",
        text: "Separates internet noise from traffic that looks chosen. Noise means the address is scanning widely, the way much of the internet does. A known service, which GreyNoise calls RIOT, is something like public DNS. Do not block that on sight.",
      },
      {
        term: "Shodan",
        text: "A catalog of services Shodan has already seen on addresses. The record can be days or weeks old. This page does not scan the host. No record does not mean the ports are closed.",
      },
      {
        term: "Honeypot",
        text: "A trap computer. Its open ports are bait. If Shodan marks the address as a honeypot, do not investigate it as a victim. The honey score runs from 0 to 1. This page treats 0.5 or more as a trap.",
      },
      {
        term: "Spamhaus ZEN",
        text: "A blocklist checked without a key. It is aimed at spam and exploited hosts. A listing is serious. No listing is not a clean bill of health.",
      },
      {
        term: "OTX",
        text: "Open Threat Exchange, run by AlienVault. People publish pulses, which are their own lists of clues. One pulse can be a careful report or a loose copy. Many pulses plus a malware name weigh more than a single mention. This source needs a key.",
      },
      {
        term: "Pulse",
        text: "One person’s published set of indicators on OTX. The address is mentioned in that set. Read who wrote it and when. A mention is not a live campaign.",
      },
      {
        term: "Malware family",
        text: "A name analysts use for a related group of malicious programs, such as a remote-access tool. A link on this page means some source tied the address to that name. It does not mean the program is running now.",
      },
      {
        term: "Adversary",
        text: "A name given to an attack group. A source may associate the address with that name. Association is not attribution. Groups share and steal infrastructure.",
      },
      {
        term: "Defender TI",
        text: "Microsoft Defender Threat Intelligence. Notes on addresses tied to attacks and campaigns in Microsoft’s data. It needs a key that most personal setups do not have. Empty here usually means we could not ask.",
      },
      {
        term: "CVE",
        text: "Common Vulnerabilities and Exposures. An identifier for a known flaw in a program, such as CVE-2024-1234. Shodan attaches these to software it recognized. Listed does not mean someone used the flaw.",
      },
      {
        term: "CPE",
        text: "Common Platform Enumeration. A structured name for a product and version. Shodan uses it when it thinks it recognized the software. Recognition can be wrong.",
      },
    ],
  },
  {
    title: "How to read a row",
    entries: [
      {
        term: "Live",
        text: "This source just answered. The row is not a saved copy.",
      },
      {
        term: "Cached",
        text: "This answer is reused from the last ask, for up to about ten minutes. The page did not ask again. A newer report can exist and not be in this copy yet.",
      },
      {
        term: "No key",
        text: "This source requires a credential. The page did not ask it. Add the key under Credentials. The key stays in this browser and is not written into the log.",
      },
      {
        term: "Limited",
        text: "The source refused for now, usually because of a rate limit. The other answers still count. Try again later. Do not read the gap as a clean result.",
      },
      {
        term: "No hit",
        text: "The source answered and had nothing on this address. That is different from no key and from an error. Nothing on one list is still not proof of safety.",
      },
      {
        term: "Banner",
        text: "The text a service sent when Shodan connected to a port. It often names the software. It is evidence of what was exposed then, not of a break-in.",
      },
      {
        term: "Passive DNS",
        text: "History of names that pointed at an address, collected by someone else. This page does not query your company’s DNS logs. A name in passive DNS may be old.",
      },
      {
        term: "Workspace log",
        text: "The list of lookups on the left. It lives in the memory of the running app. Other browser tabs on this computer can see it. It is gone when the app stops. A star means you want to come back to that address, and those rows stay at the top. The box above the list keeps only addresses that start with what you type.",
      },
      {
        term: "Our network",
        text: "Addresses, ranges, and ASNs you marked as your own. A match says do not block, unless the verdict is Suspicious or Critical. Then the note says not to close the case automatically.",
      },
      {
        term: "Raw JSON",
        text: "The same result, written as data. Use it when the summary is not enough. Copy for ticket copies the note, not this record.",
      },
    ],
  },
];
