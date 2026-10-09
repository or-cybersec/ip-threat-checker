# IP Threat Checker

Created with Grok

A first look at one public IP. The page asks services that already know the address, then turns those answers into a verdict, a score, and a short note for a ticket. It does not scan the host, and it does not use a language model.

Unknown is not clean. A source that stayed quiet is not a promise. The number on the page is this page's score, not VirusTotal's score and not AbuseIPDB's confidence.

![Start screen](docs/start.png)

![Result for the public test address 45.33.32.156, scanme.nmap.org](docs/result.png)

Licensed under MIT. See [LICENSE](LICENSE). To report a vulnerability, see [SECURITY.md](SECURITY.md).

## What a lookup does

Paste a public IPv4 or IPv6 address, or one line from a log. A trailing port (`8.8.8.8:53`) or brackets around an IPv6 address are dropped. A private or reserved address is refused. If the line has more than one public address, the page stops and lists them.

The server asks these sources at the same time:

| Source | Without a key |
|---|---|
| ipinfo | Place, ASN, and a basic record. VPN, proxy, Tor, and hosting flags need a token. |
| VirusTotal | No. Reputation, engines, and passive DNS need a key. |
| AbuseIPDB | No. |
| GreyNoise | A thin community answer on IPv4. A key adds the fuller record. |
| Shodan | InternetDB: ports, names, and known flaws. A key adds banners, the operating system, and the honeypot score. |
| WHOIS / RDAP | Yes. Registration and the abuse contact. |
| AlienVault OTX | No. |
| Defender Threat Intelligence | No. Needs a tenant id, a client id, and a client secret. |
| Spamhaus ZEN | Yes. Listed or not. Not listed is not a clean result. |

Answers arrive as each source returns. Rules then write the verdict (Critical, Suspicious, Benign, or Unknown), this page's score from 0 to 100, and the note. The note uses only sources that answered.

## What you see

- The first line says who answered, who stayed quiet, and what that does not prove.
- The note under that line is what **Copy for ticket** copies. Raw JSON is separate.
- **Clear result** sits to the left of **Analyze** and clears the page, not the log.
- The workspace log is on the left on a wide screen and below the result on a phone. Search keeps addresses that start with what you type. A star marks a row to come back to, and marked rows stay at the top.
- **Our network** is closed until you open it. A match says do not block, unless the verdict is Suspicious or Critical.
- **About** says what the page is for and where it stops. **Glossary** explains the words. **Study more** lists other sites for the basics, then a separate list of longer courses. Those sites do not recommend this page.
- **Settings** holds explanations, example addresses, the intro, open sections, source status, the last address, and a light background. They stay in this browser.
- Example buttons only fill the box. They do not start a lookup.

## Keys

Use **Credentials** in the app. Keys stay in that browser and are sent only to this app's server so it can call the source. They are not written into the log.

A browser key wins over a server key. Server keys are used only if you turn that on in Credentials. The variable names are in [.env.example](.env.example). Do not commit a filled-in `.env`.

VirusTotal, AbuseIPDB, OTX, and Defender stay quiet until a key is set. The result names them.

## Log

The log, stars, and **Our network** live in the memory of the running app. Other browser tabs on that same server can see them. They are gone when the app stops. You can delete one row, or clear rows of one verdict.

Do not put this port on the internet. Everyone who can open the page shares that log. Free source keys are for your own use, not for a public site. See [SECURITY.md](SECURITY.md).

## Run

Node.js 22:

```bash
npm install
npm run dev
```

Open http://localhost:8080

Docker, which runs the same dev server:

```bash
docker compose up
```

Same address.

## Pictures

`docs/start.png` is the start screen. `docs/result.png` is a lookup of the public test address `45.33.32.156` (`scanme.nmap.org`). Do not replace them with a picture that shows a real alert address or a key.

## Check

```bash
npm run typecheck
node --experimental-strip-types --test src/lib/intel/assess.test.ts
```
