# APO — AI-Policy Optimizer

FortiGate firewall policy analyzer. Upload a config export, get automatic
severity classification, cleanup candidates, and audit-ready Excel reports —
fully offline, no data ever leaves your machine.

## What it does

- **Policy Analysis** — parses FortiGate config + policy CSV exports into a
  single searchable view (disabled rules, zero-hit rules, expired schedules,
  missing ticket references, deletable candidates).
- **Severity classification** — rates every policy 0–7 (Unknown → Critical →
  Keep) using a NIST SP 800-41–based rule set, factoring in traffic direction,
  hit counts, rule age, and ticket history.
- **Configuration Change Review** — diffs two config exports (before/after) to
  show what changed.
- **Excel export** — color-coded, audit-ready workbook export of the full
  analysis.

## Download

Grab the latest build from **[Releases](https://github.com/yonguncho/apo-public/releases/latest)**
— no installation required, just run the `.exe` and a browser tab opens
automatically at `http://127.0.0.1:5000`.

| Edition | What you get |
|---|---|
| **Free** | Full Policy Analysis, Severity classification, and Config Change Review. CSV export. |
| **Export License ($49, one-time)** | Everything in Free, plus one-click Excel workbook export (all tabs, color-coded by severity). Perpetual license, single machine. |

Purchase an Export license at **[choiceguidelab.com](https://choiceguidelab.com)**
— the license key is emailed within a few minutes of purchase.

## Changelog

See **[Releases](https://github.com/yonguncho/apo-public/releases)** for the
version history and per-release notes.

## Support

Questions, bugs, or license issues: **choiceguidelab@gmail.com**

## License

See [LICENSE.md](LICENSE.md) for usage terms and [EULA.md](EULA.md) for the
paid Export license agreement.

## Free vs. paid — one binary

There is a single APO build. Run it without a license and you get the free
tier; activate an Export license key and the Excel export unlocks. The paid
export endpoints are enforced **server-side**, so the free tier cannot be
unlocked by tampering with the UI.

## Repository layout

```
free/   — published source tree for the shipping build (synced from the
          internal repo at release time)
paid/   — paid-edition notes; binaries are distributed via Releases only
```

Notes:
- `free/customer_rules.json` is an **optional** config file, shipped empty /
  neutral. APO works out of the box without it; fill it in only if you want to
  special-case objects in your own environment (see the `_fields` comments
  inside the file).
- `free/app/data/vuln_db.json` is a generated data file (~6 MB) and is not
  committed; it ships inside the release binary.
