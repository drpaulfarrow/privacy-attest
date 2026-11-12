"""Build, sign and verify privacy review attestations.

Member side: fragments from each repository -> company-wide draft answers ->
optional overrides -> one signed in-toto statement covering every repository.
Reviewer side: verify signature, ruleset and agent builds; read the repository
inventory, answers and overrides; check spot-check reveals.

Evidence is committed in two levels. Each repository has a Merkle root over its
own evidence. Each question's signed root is a Merkle tree over one leaf per
in-scope repository, and that leaf binds the repository name, its commit and
its evidence root. A spot check therefore proves which repository and commit a
snippet came from, and the team that owns that repository can answer it
without access to the others.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from . import AGENT_NAME, DSSE_PAYLOAD_TYPE, PREDICATE_TYPE, REVEAL_TYPE, STATEMENT_TYPE, __version__
from .crypto import (
    canonical_json, dsse_sign, dsse_verify, load_private, load_public,
    merkle_proof, merkle_root, sha256_hex, verify_merkle_proof,
)
from .scan import Draft, Evidence, repo_leaf


def now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _in_scope(inventory: list[dict], key: str = "in_scope") -> list[dict]:
    return [r for r in inventory if r[key]]


# ---------------------------------------------------------------- member side

def answers_doc(drafts: list[Draft], inventory: list[dict], cfg: dict, ruleset: dict,
                ruleset_digest: str, agent_dig: str, model: str) -> dict:
    return {
        "member": cfg.get("member", "unknown"),
        "agent": {"name": AGENT_NAME, "version": __version__, "digest": agent_dig, "model": model},
        "ruleset": {"version": ruleset["version"], "digest": ruleset_digest},
        "scanned_at": now(),
        "inventory": inventory,
        "answers": [
            {
                "id": d.qid,
                "key": d.key,
                "question": d.text,
                "agent_answer": d.answer,
                "confidence": d.confidence,
                "rationale": d.rationale,
                "evidence_count": sum(b["count"] for b in d.by_repo),
                "evidence_root": d.evidence_root,
                "evidence_by_repo": d.by_repo,
                "final_answer": d.answer,
                "override_reason": None,
            }
            for d in drafts
        ],
    }


def apply_override(doc: dict, qid: str, answer: str, reason: str) -> dict:
    if not reason or len(reason.strip()) < 10:
        raise ValueError("an override needs a reason of at least 10 characters")
    for a in doc["answers"]:
        if a["id"] == qid:
            a["final_answer"] = answer
            a["override_reason"] = reason.strip()
            a["overridden_at"] = now()
            return doc
    raise KeyError(f"no question {qid}")


def build_statement(doc: dict) -> dict:
    in_scope = _in_scope(doc["inventory"])
    subjects = []
    for r in in_scope:
        if r["commit"]:
            subjects.append({"name": f"git+{r['name']}", "digest": {"gitCommit": r["commit"]}})
        subjects.append({"name": f"scanned-tree:{r['name']}", "digest": {"sha256": r["tree_digest"]}})
    inventory = []
    for r in doc["inventory"]:
        if r["in_scope"]:
            inventory.append({
                "name": r["name"], "inScope": True, "source": r["source"], "commit": r["commit"],
                "workingTreeDirty": r["dirty"], "filesScanned": r["files_scanned"],
                "treeDigest": r["tree_digest"], "scannedAt": r["scanned_at"],
                "agentVersion": r["agent_version"], "agentDigest": r["agent_digest"],
            })
        else:
            inventory.append({"name": r["name"], "inScope": False, "reason": r["reason"]})
    answers = []
    for a in doc["answers"]:
        answers.append({
            "id": a["id"],
            "key": a["key"],
            "agentAnswer": a["agent_answer"],
            "finalAnswer": a["final_answer"],
            "overridden": a["final_answer"] != a["agent_answer"] or bool(a["override_reason"]),
            "overrideReason": a["override_reason"],
            "confidence": a["confidence"],
            "rationale": a["rationale"],
            "evidence": {"count": a["evidence_count"], "merkleRoot": a["evidence_root"],
                         "byRepo": a["evidence_by_repo"]},
        })
    return {
        "_type": STATEMENT_TYPE,
        "subject": subjects,
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "member": doc["member"],
            "agent": doc["agent"],
            "ruleset": doc["ruleset"],
            "scan": {
                "combinedAt": doc["scanned_at"],
                "reposInScope": len(in_scope),
                "reposOutOfScope": len(doc["inventory"]) - len(in_scope),
                "filesScanned": sum(r["files_scanned"] for r in in_scope),
            },
            "inventory": inventory,
            "answers": answers,
            "signedAt": now(),
            "notice": "Answers are the member's own. This attestation records how they were produced and "
                      "which repositories the member declared in and out of scope; it does not certify "
                      "that the answers are correct or that the inventory is complete.",
        },
    }


def sign(doc: dict, key_path: Path, pub_path: Path) -> dict:
    statement = build_statement(doc)
    _, kid = load_public(pub_path)
    return dsse_sign(DSSE_PAYLOAD_TYPE, canonical_json(statement), load_private(key_path), kid)


def make_reveal(doc: dict, items: list[dict], qid: str, repo: str, index: int) -> dict:
    """Reveal one evidence item from one repository, with proofs up to the signed root.

    `items` is that repository's private evidence for the question.
    """
    if not 0 <= index < len(items):
        raise IndexError(f"{repo} has {len(items)} evidence item(s) for {qid}")
    answer = next((a for a in doc["answers"] if a["id"] == qid), None)
    if answer is None:
        raise KeyError(f"no question {qid}")
    by = answer["evidence_by_repo"]
    names = [b["repo"] for b in by]
    if repo not in names:
        raise KeyError(f"{repo} is not in scope for this submission")
    k = names.index(repo)
    leaves = [i["fingerprint"] for i in items]
    if merkle_root(leaves) != by[k]["root"]:
        raise ValueError(f"the private evidence for {repo} does not match what was combined; rescan")
    commits = {r["name"]: r["commit"] for r in _in_scope(doc["inventory"])}
    repo_leaves = [repo_leaf(b["repo"], commits[b["repo"]], b["root"]) for b in by]
    item = items[index]
    return {
        "type": REVEAL_TYPE,
        "question": qid,
        "repo": repo,
        "commit": commits[repo],
        "item": {f: item[f] for f in ("repo", "qid", "signal", "path", "line", "snippet")},
        "leafIndex": index,
        "proof": merkle_proof(leaves, index),
        "repoRoot": by[k]["root"],
        "repoIndex": k,
        "repoProof": merkle_proof(repo_leaves, k),
    }


# ---------------------------------------------------------------- Reviewer side

class VerificationError(Exception):
    pass


def _names(rs: list[dict]) -> str:
    return ", ".join(r["name"] for r in rs)


def verify(envelope: dict, pub_path: Path, ruleset_digest: str,
           allowed_agent_digests: list[str] | None = None) -> tuple[dict, list[str]]:
    """Return (statement, warnings). Raise VerificationError on hard failures."""
    pub, kid = load_public(pub_path)
    try:
        payload = dsse_verify(envelope, pub, kid)
    except Exception as exc:  # noqa: BLE001
        raise VerificationError(f"signature: {exc}") from exc
    st = json.loads(payload)
    if st.get("_type") != STATEMENT_TYPE or st.get("predicateType") != PREDICATE_TYPE:
        raise VerificationError("not a privacy review statement (v0.2)")
    pred = st["predicate"]
    if pred["ruleset"]["digest"] != ruleset_digest:
        raise VerificationError("ruleset digest does not match the published ruleset")

    inv = _in_scope(pred["inventory"], "inScope")
    if not inv:
        raise VerificationError("no repositories in scope")
    commits = {r["name"]: r["commit"] for r in inv}
    for a in pred["answers"]:
        by = a["evidence"]["byRepo"]
        if [b["repo"] for b in by] != [r["name"] for r in inv]:
            raise VerificationError(f"{a['id']}: evidence does not cover exactly the in-scope repositories")
        root = merkle_root([repo_leaf(b["repo"], commits[b["repo"]], b["root"]) for b in by])
        if root != a["evidence"]["merkleRoot"] or sum(b["count"] for b in by) != a["evidence"]["count"]:
            raise VerificationError(f"{a['id']}: per-repository evidence does not add up to the signed root")

    warnings = []
    digests = {pred["agent"]["digest"]} | {r["agentDigest"] for r in inv}
    if allowed_agent_digests and not digests <= set(allowed_agent_digests):
        warnings.append("an agent build used is not on the reviewer's list of released builds")
    mixed = [r for r in inv if r["agentDigest"] != pred["agent"]["digest"]]
    if mixed:
        warnings.append(f"scanned with a different agent build from the one that combined the answers: {_names(mixed)}")
    dirty = [r for r in inv if r["workingTreeDirty"]]
    if dirty:
        warnings.append(f"scanned with uncommitted changes, so the commit alone does not identify what was scanned: {_names(dirty)}")
    no_commit = [r for r in inv if not r["commit"]]
    if no_commit:
        warnings.append(f"no git commit recorded for: {_names(no_commit)}")
    out = [r for r in pred["inventory"] if not r["inScope"]]
    if out:
        warnings.append(f"{len(out)} repositor{'y' if len(out) == 1 else 'ies'} declared out of scope by the member: {_names(out)}")
    n_over = sum(1 for a in pred["answers"] if a["overridden"])
    if n_over:
        warnings.append(f"{n_over} of {len(pred['answers'])} answer(s) overridden by the member")
    return st, warnings


def check_reveal(statement: dict, reveal: dict) -> tuple[bool, str]:
    """Is the revealed snippet part of the evidence signed for that question, repository and commit?"""
    item = reveal["item"]
    if item["repo"] != reveal["repo"] or item["qid"] != reveal["question"]:
        return False, "the reveal names a different repository or question from its item"
    leaf = Evidence(item["repo"], item["qid"], item["signal"], item["path"], item["line"], item["snippet"]).fingerprint
    if not verify_merkle_proof(leaf, reveal["proof"], reveal["repoRoot"]):
        return False, "this snippet is not part of that repository's evidence"
    pred = statement["predicate"]
    repo = next((r for r in pred["inventory"] if r["inScope"] and r["name"] == reveal["repo"]), None)
    if repo is None:
        return False, f"{reveal['repo']} is not an in-scope repository in this submission"
    if reveal.get("commit") != repo["commit"]:
        return False, "the reveal is for a different commit from the one attested"
    answer = next((a for a in pred["answers"] if a["id"] == reveal["question"]), None)
    if answer is None:
        return False, f"no question {reveal['question']} in this submission"
    if not verify_merkle_proof(repo_leaf(repo["name"], repo["commit"], reveal["repoRoot"]),
                               reveal["repoProof"], answer["evidence"]["merkleRoot"]):
        return False, "that repository's evidence is not part of the signed root for this question"
    return True, ""


def ruleset_digest_of(path: Path) -> str:
    return sha256_hex(Path(path).read_bytes())
