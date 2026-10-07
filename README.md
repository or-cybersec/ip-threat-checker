# IP Threat Checker

Created with Grok

Check a public IP before you escalate. The app asks public threat feeds, scores the address, and writes a short note. It does not scan the host.

![Start screen, with a short explanation of what the app does](docs/start.png)

![Result for the public test address scanme.nmap.org](docs/result.png)

Licensed under MIT. See [LICENSE](LICENSE).

## Run

You need [Docker](https://www.docker.com/products/docker-desktop/).

```bash
docker compose up
```

Open http://localhost:8080

Keys stay in your browser. Use Credentials in the app. Do not put them in this folder.

Without Docker, use Node.js 22:

```bash
npm install
npm run dev
```

Same address: http://localhost:8080

The log stays in the memory of the running app. Every browser tab on this computer sees the same log, and it is cleared when the app stops. Do not expose this port to the internet.
