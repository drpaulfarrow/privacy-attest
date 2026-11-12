import base64
import json
import shutil
import subprocess
from pathlib import Path

import pytest
from click.testing import CliRunner

from privacy_attest.cli import main

SAMPLE = Path(__file__).parent.parent / "examples" / "acme-dsp"


@pytest.fixture()
def repo(tmp_path):
    dst = tmp_path / "acme-dsp"
    shutil.copytree(SAMPLE, dst, ignore=shutil.ignore_patterns(".git", ".attest"))
    for cmd in (["init", "-q"], ["add", "-A"],
                ["-c", "user.email=t@t.example", "-c", "user.name=t", "commit", "-qm", "x"]):
        subprocess.run(["git", "-C", str(dst), *cmd], check=True)
    return dst


def run(*args, ok=True):
    r = CliRunner().invoke(main, list(map(str, args)))
    if ok:
        assert r.exit_code == 0, r.output
    return r


def setup(repo, tmp_path):
    run("init", "--repo", repo, "--member", "Acme", "--first-party", "acme-dsp.example")
    run("scan", "--repo", repo)
    sub = tmp_path / "sub.json"
    return sub


def test_finds_the_planted_gpc_gap(repo, tmp_path):
    setup(repo, tmp_path)
    doc = json.loads((repo / ".attest" / "answers.json").read_text())
    q1 = next(a for a in doc["answers"] if a["id"] == "Q1")
    assert q1["agent_answer"] == "Partially"
    assert "web/tag.js:18" in q1["rationale"]
    q5 = next(a for a in doc["answers"] if a["id"] == "Q5")
    assert "acme-dsp.example" not in q5["agent_answer"]
    assert "collect.partner-analytics.example" in q5["agent_answer"]


def test_sign_verify_and_no_code_leaves(repo, tmp_path):
    sub = setup(repo, tmp_path)
    run("override", "Q3", "--answer", "No", "--reason", "Contextual segment only, no personal data.", "--repo", repo)
    run("sign", "--repo", repo, "-o", sub)
    raw = sub.read_text()
    payload = base64.b64decode(json.loads(raw)["payload"]).decode()
    for code in ("sendBeacon", "navigator.geolocation", "requests.post", "Diabetes"):
        assert code not in payload
    out = run("verify", sub, "--member-key", repo / ".attest" / "member_key.pub.pem").output
    assert "VERIFIED" in out and "OVERRIDDEN" in out and "agent said: Yes" in out


def test_tampered_answer_fails(repo, tmp_path):
    sub = setup(repo, tmp_path)
    run("sign", "--repo", repo, "-o", sub)
    env = json.loads(sub.read_text())
    st = json.loads(base64.b64decode(env["payload"]))
    st["predicate"]["answers"][0]["finalAnswer"] = "Yes"
    env["payload"] = base64.b64encode(json.dumps(st).encode()).decode()
    sub.write_text(json.dumps(env))
    r = run("verify", sub, "--member-key", repo / ".attest" / "member_key.pub.pem", ok=False)
    assert r.exit_code == 1 and "FAILED" in r.output


def test_wrong_key_fails(repo, tmp_path):
    sub = setup(repo, tmp_path)
    run("sign", "--repo", repo, "-o", sub)
    other = tmp_path / "other"
    other.mkdir()
    subprocess.run(["git", "-C", str(other), "init", "-q"], check=True)
    run("init", "--repo", other, "--member", "Someone else")
    r = run("verify", sub, "--member-key", other / ".attest" / "member_key.pub.pem", ok=False)
    assert r.exit_code == 1


def test_reveal_matches_and_forged_reveal_fails(repo, tmp_path):
    sub = setup(repo, tmp_path)
    run("sign", "--repo", repo, "-o", sub)
    rev = tmp_path / "rev.json"
    run("reveal", "Q1", "--item", "6", "--repo", repo, "-o", rev)
    key = repo / ".attest" / "member_key.pub.pem"
    assert "MATCH" in run("check-reveal", sub, rev, "--member-key", key).output
    forged = json.loads(rev.read_text())
    forged["item"]["snippet"] = "if (!optedOut) { navigator.sendBeacon(...) }"
    rev.write_text(json.dumps(forged))
    r = run("check-reveal", sub, rev, "--member-key", key, ok=False)
    assert r.exit_code == 1 and "NO MATCH" in r.output


def test_override_needs_a_reason(repo, tmp_path):
    setup(repo, tmp_path)
    r = run("override", "Q1", "--answer", "Yes", "--reason", "ok", "--repo", repo, ok=False)
    assert r.exit_code != 0


def test_changed_ruleset_fails(repo, tmp_path):
    sub = setup(repo, tmp_path)
    run("sign", "--repo", repo, "-o", sub)
    alt = tmp_path / "ruleset.yaml"
    alt.write_text("version: '0.2'\nquestions: []\n")
    r = run("verify", sub, "--member-key", repo / ".attest" / "member_key.pub.pem", "--ruleset", alt, ok=False)
    assert "ruleset digest" in r.output
