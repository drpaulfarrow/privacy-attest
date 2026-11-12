#!/usr/bin/env bash
# End-to-end demo: a member with several repositories, reviewed and attested once.
# (PowerShell users: demo.ps1 does the same.)
set -euo pipefail
cd "$(dirname "$0")/examples/acme"
REPOS="acme-web-tag acme-bidder acme-audiences"
rm -rf privacy-review acme-submission.json acme-member-key.pub.pem reveal-*.json
for r in $REPOS; do
  rm -rf "$r/.attest"
  [ -d "$r/.git" ] || (cd "$r" && git init -q && git add -A && \
    git -c user.email=demo@acme-dsp.example -c user.name=Demo commit -qm "Sample member repository")
done
mkdir privacy-review

echo "== CI for acme-audiences: scan in its own pipeline, keep the code there, hand over a fragment =="
privacy-attest scan-repo --repo acme-audiences

echo; echo "== MEMBER privacy lead: set up the review and declare the repository inventory =="
cd privacy-review
privacy-attest init --member "Acme DSP Inc." --first-party acme-dsp.example
privacy-attest repo add acme-web-tag --path ../acme-web-tag
privacy-attest repo add acme-bidder --path ../acme-bidder
privacy-attest repo add acme-audiences --fragment ../acme-audiences/.attest/fragment.json
privacy-attest repo exclude acme-ml-sandbox --reason "Research notebooks on synthetic data; nothing deployed to production."
privacy-attest repo list

echo; echo "== MEMBER: scan the local repositories, combine with the fragment, draft company-wide answers =="
privacy-attest scan
echo; echo "== MEMBER: look at the evidence for Q1 (private, never sent to the reviewer) =="
privacy-attest evidence Q1
echo; echo "== MEMBER: disagree with Q3, with a reason, then sign =="
privacy-attest override Q3 --answer "No" \
  --reason "Segment 1004 is contextual only: built from page content, never from a person's health data."
privacy-attest sign -o ../acme-submission.json
cp .attest/member_key.pub.pem ../acme-member-key.pub.pem
cd ..

echo; echo "== REVIEWER: verify the submission (no code received) =="
privacy-attest verify acme-submission.json --member-key acme-member-key.pub.pem
echo; echo "== SPOT CHECK: the reviewer picks Q1 item 7; the member reveals it with proof of repository and commit =="
(cd privacy-review && privacy-attest reveal Q1 --item 7 -o ../reveal-Q1-7.json)
privacy-attest check-reveal acme-submission.json reveal-Q1-7.json --member-key acme-member-key.pub.pem
