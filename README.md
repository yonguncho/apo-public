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

## Repository layout

```
app/    — legacy source tree (pre-v59), kept for reference only
free/   — free-edition source tree (pre-v60), kept for reference only
paid/   — paid-edition changelog notes; binaries are distributed via Releases
```

> **Note:** the `app/` and `free/` source trees predate the current shipping
> build and are not kept in sync release-to-release. They are not meant to be
> built from directly — always download from Releases above.
