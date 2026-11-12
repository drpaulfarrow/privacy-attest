import base64
import json
import shutil
import subprocess
from pathlib import Path

import pytest
from click.testing import CliRunner

from privacy_attest.attest import sign as sign_doc
from privacy_attest.cli import main

SAMPLE = Path(__file__).parent.parent / "examples" / "acme"
REPOS = ["acme-web-tag", "acme-bidder", "acme-audiences"]


def run(*args, ok=True):
    r = CliRunner().invoke(main, list(map(str, args)))
    if ok:
        assert r.exit_code == 0, r.output
    return r


@pytest.fixture()
def acme(tmp_path):
    for name in REPOS:
        dst = tmp_path / name
        shutil.copytree(SAMPLE / name, dst, ignore=shutil.ignore_patterns(".git", ".attest"))
        for cmd in (["init", "-q"], ["add", "-A"],
                    ["-c", "user.email=t@t.example", "-c", "user.name=t", "commit", "-qm", "x"]):
            subprocess.run(["git", "-C", str(dst), *cmd], check=True, capture_output=True)
    ws = tmp_path / "privacy-review"
    ws.mkdir()
    # acme-audiences is scanned "in its own CI" and handed over as a fragment.
    run("scan-repo", "--repo", tmp_path / "acme-audiences")
    run("init", "--workspace", ws, "--member", "Acme DSP Inc.", "--first-party", "acme-dsp.example")
    run("repo", "add", "acme-web-tag", "--path", tmp_path / "acme-web-tag", "--workspace", ws)
    run("repo", "add", "acme-bidder", "--path", tmp_path / "acme-bidder", "--workspace", ws)
    run("repo", "add", "acme-audiences", "--fragment", tmp_path / "acme-audiences" / ".attest" / "fragment.json",
        "--workspace", ws)
    run("repo", "exclude", "acme-ml-sandbox", "--reason", "Research notebooks on synthetic data only.",
        "--workspace", ws)
    run("scan", "--workspace", ws)
    return tmp_path, ws


def answers(ws):
    return {a["id"]: a for a in json.loads((ws / ".attest" / "answers.json").read_text(encoding="utf-8"))["answers"]}


def submit(ws, tmp_path):
    sub = tmp_path / "sub.json"
    run("sign", "--workspace", ws, "-o", sub)
    return sub, ws / ".attest" / "member_key.pub.pem"


def test_answers_combine_across_repos(acme):
    _, ws = acme
    a = answers(ws)
    assert a["Q1"]["agent_answer"] == "Partially"
    assert "acme-web-tag/web/tag.js:18" in a["Q1"]["rationale"]
    assert "acme-audiences/pipelines/partner_export.py:15" in a["Q1"]["rationale"]
    assert a["Q2"]["agent_answer"] == "Yes"
    assert a["Q3"]["agent_answer"] == "Yes"
    assert a["Q4"]["agent_answer"] == "Yes, longest 395 days"
    q5 = a["Q5"]["agent_answer"]
    for host in ("bid.exchange-one.example", "collect.partner-analytics.example",
                 "sync.audience-partner.example", "upload.data-partner.example"):
        assert host in q5
    assert "acme-dsp.example" not in q5
    assert [b["repo"] for b in a["Q1"]["evidence_by_repo"]] == REPOS


def test_one_repo_alone_misses_the_pipeline_gap(acme):
    tmp_path, _ = acme
    solo = tmp_path / "acme-web-tag"
    run("init", "--repo", solo, "--member", "Acme DSP Inc.", "--first-party", "acme-dsp.example")
    run("scan", "--repo", solo)
    assert "partner_export" not in answers(solo)["Q1"]["rationale"]


def test_verify_shows_inventory_and_no_code(acme):
    tmp_path, ws = acme
    sub, key = submit(ws, tmp_path)
    payload = base64.b64decode(json.loads(sub.read_text())["payload"]).decode()
    for code in ("sendBeacon", "requests.post", "Diabetes", "members"):
        assert code not in payload
    out = run("verify", sub, "--member-key", key).output
    assert "VERIFIED" in out and "3 repo(s) in scope" in out
    assert "out of scope  acme-ml-sandbox" in out and "synthetic data" in out
    assert "declared out of scope" in out
    st = json.loads(payload)
    assert {s["name"] for s in st["subject"]} >= {f"git+{r}" for r in REPOS}


def test_reveal_from_fragment_repo(acme):
    tmp_path, ws = acme
    sub, key = submit(ws, tmp_path)
    out = run("evidence", "Q1", "--workspace", ws).output
    line = next(l for l in out.splitlines() if "partner_export.py:15" in l)
    item = int(line.split("]")[0].strip("["))
    rev = tmp_path / "rev.json"
    run("reveal", "Q1", "--item", item, "--workspace", ws, "-o", rev)
    r = run("check-reveal", sub, rev, "--member-key", key)
    assert "MATCH: acme-audiences/pipelines/partner_export.py:15" in r.output

    original = json.loads(rev.read_text())
    forged = json.loads(json.dumps(original))
    forged["item"]["snippet"] = "if not opted_out: requests.post(PARTNER_URL, ...)"
    rev.write_text(json.dumps(forged))
    assert run("check-reveal", sub, rev, "--member-key", key, ok=False).exit_code == 1

    # Same snippet, claimed to come from another repository: fails.
    moved = json.loads(json.dumps(original))
    moved["repo"] = moved["item"]["repo"] = "acme-bidder"
    rev.write_text(json.dumps(moved))
    assert "NO MATCH" in run("check-reveal", sub, rev, "--member-key", key, ok=False).output

    # Right snippet, wrong commit: fails.
    stale = json.loads(json.dumps(original))
    stale["commit"] = "0" * 40
    rev.write_text(json.dumps(stale))
    assert "different commit" in run("check-reveal", sub, rev, "--member-key", key, ok=False).output


def test_evidence_without_private_file_hides_snippet(acme):
    tmp_path, ws = acme
    (tmp_path / "acme-audiences" / ".attest" / "evidence.private.json").unlink()
    run("scan", "--workspace", ws)
    out = run("evidence", "Q1", "--workspace", ws).output
    assert "snippet held with acme-audiences" in out
    item = next(i for i, l in enumerate(l for l in out.splitlines() if l.startswith("[")) if "partner_export" in l)
    r = run("reveal", "Q1", "--item", item, "--workspace", ws, ok=False)
    assert "--evidence" in r.output


def test_fragment_from_other_ruleset_is_rejected(acme, tmp_path):
    _, ws = acme
    rules = tmp_path / "rules.yaml"
    src = Path(__file__).parent.parent / "privacy_attest" / "ruleset" / "privacy-ruleset-v0.1.yaml"
    rules.write_bytes(src.read_bytes() + b"\n# tweaked\n")
    run("scan-repo", "--repo", tmp_path / "acme-audiences", "--ruleset", rules)
    r = run("scan", "--workspace", ws, ok=False)
    assert "different ruleset" in r.output


def test_inconsistent_evidence_summary_fails_verification(acme):
    tmp_path, ws = acme
    d = ws / ".attest"
    doc = json.loads((d / "answers.json").read_text(encoding="utf-8"))
    doc["answers"][0]["evidence_by_repo"][2]["root"] = "00" * 32   # hide the pipeline evidence
    env = sign_doc(doc, d / "member_key.pem", d / "member_key.pub.pem")
    sub = tmp_path / "bad.json"
    sub.write_text(json.dumps(env))
    r = run("verify", sub, "--member-key", d / "member_key.pub.pem", ok=False)
    assert "does not add up" in r.output


def test_exclusion_needs_a_reason(acme):
    _, ws = acme
    r = run("repo", "exclude", "acme-legacy", "--reason", "old", "--workspace", ws, ok=False)
    assert r.exit_code != 0
