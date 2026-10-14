# APO — Audit & Policy Optimizer

Offline FortiGate firewall policy audit. Open a configuration export, get a
verdict for every policy — with the **reason** next to it and the **next
action** after it — then migrate address changes with every reference moved
together. One Windows executable, no installation, no server. The
configuration never leaves your machine and APO never writes to your
firewall unless you tell it to.

Current release: **v134** (2026-09-21). Interface in English and Korean.

## What it does

**Policy audit**

- Reads a `show full-configuration` export (and, optionally, the per-policy
  hit-count / last-used CSV from the GUI, or collects both from the device
  over its REST API with a read-only token).
- Grades every firewall policy and writes the reason beside the grade —
  disabled, expired one-time schedule, Any/All, risky plaintext services
  (TELNET / FTP / …), temporary policies with no ticket, zero hits on a path
  where zero hits is normal (backup / DR interfaces), and so on. Your own
  user IP ranges tell it which policies carry user traffic and which carry
  server-to-server traffic.
- Separates the grade from what to do about it: *disable now*, *review*,
  *remove just the risky service and keep the policy*, *register a ticket*,
  or *decide after the policies above it* — and gives you the FortiGate CLI
  for each item, with a copy button.
- **Unreachable policy detection**: a policy is reported only when a single
  always-on policy above it *provably* matches every packet it could match
  (source, destination, service and interfaces all contained). Policies that
  use FQDN, geography, ISDB or user objects, or negation, are skipped and
  listed — never guessed. Routing and NAT are not modelled.
- Judgement criteria live in a profile you can edit; the defaults are
  neutral.

**Address migration**

- Enter the old IP or range; APO finds every place it is referenced,
  including sections a policy report never shows.
- Map each address to its new value (type, paste a list, or import CSV),
  preview every line that will change — with a warning on the change that
  could cut off your own access to the device — then build the new
  configuration file. The produced file is read back to confirm no old value
  is left behind.

**Also**

- Configuration change review: diff two exports, grouped by what changed.
- Verification: sample APO's calls against your own firewall before you
  trust them.
- Audit-ready Excel workbooks (licensed — see below).

## Download

**[Latest release](https://github.com/yonguncho/apo-public/releases/latest)**
— fixed download links:

```
https://github.com/yonguncho/apo-public/releases/latest/download/APO.exe
https://github.com/yonguncho/apo-public/releases/latest/download/SHA256SUMS.txt
```

Run `APO.exe`; a browser tab opens at `http://127.0.0.1:5000` (set `APO_PORT`
to change the port). Nothing is installed and nothing is sent anywhere.

The executable is not code-signed, so Windows SmartScreen or your browser
may warn on first run. Compare the hash before you trust it:

```powershell
Get-FileHash .\APO.exe -Algorithm SHA256
```

The value must match the line for `APO.exe` in `SHA256SUMS.txt` of the same
release.

### Docker

If your endpoint policy blocks unknown executables, the same build is
published as a container image. Pin the tag to the release you mean; do not
use `:latest`.

```powershell
$env:APO_TOKEN = -join ((1..32) | ForEach-Object { '{0:x}' -f (Get-Random -Max 16) })
docker pull jayden81/apo:v134
docker run -d --name apo-app -p 127.0.0.1:5000:5000 -e APO_TOKEN=$env:APO_TOKEN -v apo-data:/app/data --restart unless-stopped jayden81/apo:v134
```

`APO_TOKEN` is the access token for the local UI (at least 16 characters);
the container refuses to start without one. Open `http://127.0.0.1:5000` and
enter the token once.

## Free and licensed — one binary

There is a single build. Without a licence key you get everything except
exports; with one, the export features unlock. The export endpoints are
enforced server-side, so the free tier cannot be unlocked from the UI.

| | Free | Licensed |
|---|---|---|
| Policy audit — grades, reasons, next actions, action plan with CLI | ✔ | ✔ |
| Unreachable policy detection | ✔ | ✔ |
| Address migration, including building the new configuration file | ✔ | ✔ |
| Configuration change review, verification | ✔ | ✔ |
| Excel audit workbook, evidence workbook, scoped reports | — | ✔ |
| Action-plan exports (CSV, Postman) and applying changes to the device over the API | — | ✔ |
| Batch report (many devices in one run) and white-label report branding | — | MSP / Consultant |

Applying changes to the device is the only action that writes to your
firewall and cannot be undone from APO, so it is kept behind a licence.
Free users still get the same CLI in the action plan to run themselves.

| Licence | Price | Scope |
|---|---|---|
| **Single organisation** | $199, one-time | Audit the firewalls of one organisation. One named person, any machine they work from. One year of updates; the versions released in that year keep working with your key forever. |
| **MSP / Consultant** | $699, one-time | Everything above, across all your client organisations, plus batch reports and white-label workbooks. |

Buy at **[choiceguidelab.com](https://choiceguidelab.com)** — the key is
emailed after purchase. Full terms: [EULA.md](EULA.md).

## Changelog

See **[Releases](https://github.com/yonguncho/apo-public/releases)** for the
version history and per-release notes.

## Support

Questions, bugs, or licence issues: **choiceguidelab@gmail.com**

## License

See [LICENSE.md](LICENSE.md) for usage terms and [EULA.md](EULA.md) for the
paid licence agreement.

## Repository layout

```
free/      — published source tree of the application (last synced at v95;
             the Releases binaries are the current version)
paid/      — notes only; binaries are distributed via Releases
preview/   — static HTML previews of the main screens
```

Notes:
- `free/customer_rules.json` is an **optional** file, shipped neutral. APO
  works without it; fill it in only to special-case objects in your own
  environment.
- `free/app/data/vuln_db.json` is a generated data file (~6 MB) and is not
  committed; it ships inside the release binary.
