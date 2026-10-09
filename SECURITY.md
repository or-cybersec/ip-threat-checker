# Security policy

IP Threat Checker is a local first look. It is not a hosted service.

## Report a vulnerability

Open a private security advisory on this repository. Do not open a public issue for a security report.

Do not include API keys, a filled-in `.env`, or addresses from a real alert. Describe the version (git commit) and the steps.

## What to expect

There is no bug bounty. A report gets a look. If the report is valid, the fix goes in a normal commit on `main`.

## Use that is out of scope

- Putting the app on the public internet with your own source keys. Those keys are for you. Other people will spend the quota, and several providers forbid using a free key as a public proxy.
- Expecting the workspace log to be private. While the app is running, every browser that can open it sees the same log and the same **Our network** list.
- Scanning, exploitation, or sending traffic to the address you looked up. This app does not do that, and reports that ask it to are out of scope.
