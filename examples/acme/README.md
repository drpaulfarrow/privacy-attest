# Acme (fictional multi-repository member)

A made-up ad tech company whose code is split the way real members' code
usually is. Used by `demo.ps1` / `demo.sh` to show a review across repositories.
All domains are reserved `.example` names.

| Repository | What it holds | How the demo scans it |
|---|---|---|
| `acme-web-tag` | Pixel loaded on advertiser sites | Locally, by the privacy lead |
| `acme-bidder` | OpenRTB bid requests, bid log retention | Locally, by the privacy lead |
| `acme-audiences` | Segment taxonomy, retention, nightly partner export | In "its own CI": `scan-repo` produces a fragment |
| `acme-ml-sandbox` | Not present | Declared out of scope, with a reason the reviewer sees |

Planted findings:

- `acme-web-tag/web/tag.js:18` sends analytics for every visitor, ignoring GPC.
- `acme-audiences/pipelines/partner_export.py:15` ships audience memberships to a
  data partner with no opt-out check. A review of the tag and bidder alone would
  never see it.
- `acme-audiences/segments/taxonomy.csv` has a health segment.
- `acme-audiences/config/retention.yaml` keeps memberships for 395 days.

The `privacy-review` folder is created by the demo: it is the privacy lead's
review workspace, holding the config, the signing key and the combined answers.
