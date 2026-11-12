# privacy-attest (prototype)

A privacy review agent that companies run on their own code, for a reviewer such as
a self-regulatory body, an auditor or a customer. It drafts answers
to Privacy Review questions, lets the company (the "member") change any answer with a stated
reason, and signs the result. The reviewer receives the answers, the reasons, the
member's repository inventory and fingerprints of the evidence. It never
receives code.

Members rarely keep everything in one repository: the tag, the bidder, the
audience pipeline and the infrastructure usually live apart, with different
teams and different CI. So each repository is scanned where it lives, and the
results are combined into **one company-wide submission**.

```
member's environment                                                 reviewer
──────────────────────────────────────────────────────────          ─────────────────────────
repo A (laptop) ─┐                                                   verify signature
repo B (laptop) ─┼─▶ scan ─▶ company-wide   ─▶ override ─▶ sign ────▶ check ruleset + agent builds
repo C (its CI) ─┘    ▲      draft answers      (reason)              read inventory: in scope,
   │ scan-repo        │                                               out of scope + reasons
   └─▶ fragment ──────┘   (findings + fingerprints, no code)          read answers + overrides
repo D: declared out of scope, with a reason                          flag mismatches with
                                                                      outside-in tests
each repo keeps its own .attest/evidence.private.json (snippets)
spot check: that repo's owner reveals one item ────────────────────▶ check-reveal (proof of
                                                                      repo, commit, signature)
```

## Try it

Windows PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python -m pip install -e . pytest
powershell -ExecutionPolicy Bypass -File .\demo.ps1          # add -Pause to step through it live
```

macOS / Linux / Git Bash: `pip install -e .` then `./demo.sh`.

The demo uses a fictional company in [examples/acme](examples/acme/README.md) with
three repositories, one of them scanned "in its own CI", and one more declared
out of scope. A single-repository sample is in `examples/acme-dsp`.

## Member side

**Several repositories.** In each repository's CI (or on any machine that has it):

```bash
privacy-attest scan-repo --repo . --name acme-audiences
# writes .attest/fragment.json (shareable inside the company, no code)
# and .attest/evidence.private.json (snippets; stays with this repository)
```

In the privacy lead's review workspace:

```bash
privacy-attest init --member "Acme DSP Inc." --first-party acme-dsp.example
privacy-attest repo add acme-web-tag   --path ../acme-web-tag              # scanned by `scan`
privacy-attest repo add acme-audiences --fragment ../ci/acme-audiences/fragment.json
privacy-attest repo exclude acme-ml-sandbox --reason "Research notebooks on synthetic data"
privacy-attest scan                       # company-wide answers
privacy-attest evidence Q1                # what the agent relied on, across repos (private)
privacy-attest override Q3 --answer "No" --reason "Contextual segment only ..."
privacy-attest sign -o submission.json
```

**One repository.** Skip the `repo` commands: run `init` and `scan` inside the
repository and it is treated as a one-entry inventory.

## Reviewer side

```bash
privacy-attest verify submission.json --member-key acme.pub.pem
privacy-attest check-reveal submission.json reveal-Q1-7.json --member-key acme.pub.pem
```

Spot check, on a screen-share, member side:

```bash
privacy-attest reveal Q1 --item 7          # shows one snippet and writes a proof file
privacy-attest reveal Q1 --item 7 --evidence path/to/that-repo/.attest/evidence.private.json
```

The second form is for a repository scanned elsewhere: whoever holds that
repository's private evidence answers the spot check, without access to the others.

## What is attested, and what is not

The submission is an [in-toto](https://github.com/in-toto/attestation) Statement in
a DSSE envelope, the same format used for software supply-chain attestations.

| Recorded and signed | Kept private by the member |
|---|---|
| Repository inventory: every repo in scope, and every repo declared out of scope with its reason | The code itself |
| Per repo: git commit, digest of every file scanned, when and with which agent build | File contents and snippets |
| Agent version, agent source digest, model used | Full evidence lists |
| Ruleset version and digest | |
| Agent's answer, final answer, override reason | |
| Per question: evidence count and Merkle root, and the same per repository | |

Evidence is committed in two levels. Each repository has a Merkle root over its
own evidence; each question's signed root is a tree with one leaf per in-scope
repository, binding its name, commit and evidence root. So a reveal proves the
snippet, the repository and the commit, and the reviewer checks that per-repository
counts and roots add up to what was signed. Leaves and inner nodes are hashed
with different prefixes (as in RFC 6962).

The signature proves *this agent, with these rules, ran on these commits, the
member declared this inventory and chose these answers*. It does not prove the
answers are true, that the inventory is complete, or that the commits are what
runs in production. That is why the design pairs it with:

1. **Visible overrides and exclusions.** Members can change any answer or leave a
   repository out; the agent's original answer, the repository's name and the
   member's reason travel with it.
2. **Spot checks.** The reviewer picks an evidence item; the member reveals it with a
   Merkle proof that it was part of what was signed, for that repository and
   commit. Forged snippets, moved snippets and stale commits fail.
3. **Outside-in tests.** The reviewer checks live behaviour (for example GPC handling
   on the member's site) and investigates where it disagrees with the attestation.
   An endpoint seen in live traffic that no in-scope repository mentions points
   to a missing repository. Not in this prototype.

Rationales and the inventory name repositories, file paths and line numbers (for
example `acme-web-tag/web/tag.js:18`). Paths are not code, but members should
know they are shared.

## The five starter questions

Each question is answered once for the whole company. Each repository's scan
collects evidence; the combine step decides the answer from all of it.

| ID | Question | How the prototype answers, across repositories |
|---|---|---|
| Q1 | Is Global Privacy Control honoured for third-party calls? | GPC reads and third-party calls anywhere; "Partially" if any call in any repo is outside an opt-out `if` block |
| Q2 | Is precise geolocation collected? | Browser geolocation APIs, coordinate fields, coarsening, in any repo |
| Q3 | Are segments built on sensitive categories? | Sensitive terms in segment and taxonomy files in any repo |
| Q4 | Is there a retention limit for event data? | Retention and TTL settings; reports the longest and where it is |
| Q5 | Which third parties receive data? | External hosts in all repos, minus first-party domains |

Questions live in `privacy_attest/ruleset/privacy-ruleset-v0.1.yaml`. Counsel owns the
wording and legal references; engineering owns the signals. Fragments scanned with
a different ruleset are refused when combining.

## Limits of the prototype

- Detection is regular expressions plus a brace/indent heuristic. It will miss
  things and flag others, and it does not follow data across repositories (a GPC
  flag set in one service and checked in another is matched only by name). A
  production agent would use parsers, or a model step (`--model`, optional and
  off by default; snippets go only to the member's chosen provider, never the reviewer).
- Fragments are not signed on their own; only the combined submission is, with the
  member key. Production could have each repository's CI sign its fragment.
- Keys are local Ed25519 pairs registered with the reviewer. Production should sign
  with Sigstore so keys are tied to a verified company identity and logged.
- Code is not the whole truth: tag-manager setups, consent-platform settings,
  warehouse jobs and contracts need connectors or human answers.
- No outside-in test runner yet.

All domains in the sample repositories are reserved `.example` names.
