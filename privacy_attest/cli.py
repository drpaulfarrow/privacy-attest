"""Command line interface.

Member commands
  init                   set up a review workspace (or a single repository) with a signing key
  repo add/exclude/list  declare which repositories are in and out of scope
  scan-repo              scan one repository where it lives (laptop or its CI); writes a fragment
  scan                   scan or collect every in-scope repository, draft company-wide answers
  evidence, override, sign, reveal
Reviewer commands
  verify, check-reveal

A workspace with no repositories added is treated as a single repository: the
workspace folder itself. That is the simplest case and needs no `repo` commands.
"""
from __future__ import annotations

import copy
import json
import os
import sys
from pathlib import Path

import click
import yaml

from . import FRAGMENT_TYPE, __version__
from .attest import (
    VerificationError, answers_doc, apply_override, check_reveal, make_reveal,
    ruleset_digest_of, sign as sign_doc, verify as verify_env,
)
from .crypto import generate_keypair
from .scan import agent_digest, decide, load_ruleset, scan_repo

ATTEST_DIR = ".attest"


def _dir(ws) -> Path:
    return Path(ws).resolve() / ATTEST_DIR


def _load(p: Path):
    p = Path(p)
    if not p.exists():
        raise click.ClickException(f"{p} not found; run the earlier step first")
    return json.loads(p.read_text(encoding="utf-8"))


def _write(p: Path, obj) -> None:
    p = Path(p)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _wrap(s: str, width: int) -> str:
    return s if len(s) <= width else s[: width - 1] + "…"


def _cfg(ws) -> dict:
    p = _dir(ws) / "config.yaml"
    if not p.exists():
        raise click.ClickException(f"{p} not found; run `privacy-attest init` first")
    return yaml.safe_load(p.read_text(encoding="utf-8"))


def _save_cfg(ws, cfg: dict) -> None:
    (_dir(ws) / "config.yaml").write_text(yaml.safe_dump(cfg, sort_keys=False), encoding="utf-8")


def _rel(path: str, ws) -> str:
    target = Path(path).resolve()
    try:
        rel = os.path.relpath(target, Path(ws).resolve())
    except ValueError:  # different drive on Windows
        rel = str(target)
    return rel.replace("\\", "/")


def _entries(cfg: dict) -> list[dict]:
    return cfg.get("repos") or [{"name": cfg["repo_name"], "path": "."}]


def _write_repo_outputs(repo_root: Path, fragment: dict, private: dict) -> tuple[Path, Path]:
    d = Path(repo_root).resolve() / ATTEST_DIR
    d.mkdir(parents=True, exist_ok=True)
    if not (d / ".gitignore").exists():
        (d / ".gitignore").write_text("*\n", encoding="utf-8")
    _write(d / "fragment.json", fragment)
    _write(d / "evidence.private.json", private)
    return d / "fragment.json", d / "evidence.private.json"


def _snippets(private_path: str | None) -> dict:
    """fingerprint -> snippet, from one repository's private evidence (if it is here)."""
    if not private_path or not Path(private_path).exists():
        return {}
    return {i["fingerprint"]: i["snippet"]
            for items in _load(Path(private_path)).values() for i in items}


def workspace_option(f):
    return click.option("--workspace", "--repo", "ws", default=".", show_default=True,
                        help="Review workspace. For a single repository, the repository itself.")(f)


@click.group()
@click.version_option(__version__)
def main():
    """Privacy review agent: run it on your code, sign the answers, send only the attestation."""


# ---------------------------------------------------------------- member side: setup

@main.command()
@workspace_option
@click.option("--member", required=True, help="Member company name as registered with the reviewer.")
@click.option("--repo-name", default=None, help="Repository name when the workspace is a single repository.")
@click.option("--first-party", multiple=True, help="Your own domains, excluded from third-party recipients.")
def init(ws, member, repo_name, first_party):
    """Create .attest/ with a config file and a signing key pair."""
    d = _dir(ws)
    d.mkdir(parents=True, exist_ok=True)
    cfg = {"member": member, "repo_name": repo_name or Path(ws).resolve().name,
           "first_party_domains": list(first_party), "ignore_domains": ["example.com"],
           "exclude": [], "repos": []}
    _save_cfg(ws, cfg)
    kid = generate_keypair(d / "member_key.pem", d / "member_key.pub.pem")
    (d / ".gitignore").write_text("*\n", encoding="utf-8")
    click.echo(f"Created {d}. Signing key {kid}.")
    click.echo("Register .attest/member_key.pub.pem with the reviewer once. Keep member_key.pem private.")
    click.echo("One repository: run `privacy-attest scan` here. Several: declare them with `privacy-attest repo add`.")


@main.group()
def repo():
    """Declare which repositories are in scope. The reviewer sees this inventory."""


@repo.command("add")
@click.argument("name")
@click.option("--path", "path_", default=None, help="Local checkout; `scan` scans it directly.")
@click.option("--fragment", default=None, help="fragment.json produced by `scan-repo` elsewhere (e.g. that repo's CI).")
@click.option("--exclude", "excludes", multiple=True, help="Glob of files to skip in this repository.")
@workspace_option
def repo_add(name, path_, fragment, excludes, ws):
    """Add a repository to the review, by local path or by a fragment scanned elsewhere."""
    if bool(path_) == bool(fragment):
        raise click.ClickException("give exactly one of --path or --fragment")
    cfg = _cfg(ws)
    entry = {"name": name, "in_scope": True}
    if path_:
        entry["path"] = _rel(path_, ws)
    else:
        entry["fragment"] = _rel(fragment, ws)
    if excludes:
        entry["exclude"] = list(excludes)
    cfg["repos"] = [r for r in cfg.get("repos", []) if r["name"] != name] + [entry]
    _save_cfg(ws, cfg)
    click.echo(f"{name} in scope ({'scanned here' if path_ else 'fragment from elsewhere'}).")


@repo.command("exclude")
@click.argument("name")
@click.option("--reason", required=True, help="Why this repository is out of scope. Sent to the reviewer.")
@workspace_option
def repo_exclude(name, reason, ws):
    """Declare a repository out of scope. Its name and your reason are attested."""
    if len(reason.strip()) < 10:
        raise click.ClickException("an exclusion needs a reason of at least 10 characters")
    cfg = _cfg(ws)
    cfg["repos"] = [r for r in cfg.get("repos", []) if r["name"] != name] + \
        [{"name": name, "in_scope": False, "reason": reason.strip()}]
    _save_cfg(ws, cfg)
    click.echo(f"{name} out of scope. The reviewer will see the name and your reason.")


@repo.command("list")
@workspace_option
def repo_list(ws):
    """Show the repository inventory."""
    for e in _entries(_cfg(ws)):
        if not e.get("in_scope", True):
            click.echo(f"  {e['name']:20} out of scope   {e['reason']}")
        else:
            click.echo(f"  {e['name']:20} in scope       {e.get('path') or e.get('fragment')}")


# ---------------------------------------------------------------- member side: scanning

@main.command("scan-repo")
@click.option("--repo", "repo_path", default=".", show_default=True, help="Repository to scan.")
@click.option("--name", default=None, help="Repository name as listed in the review inventory.")
@click.option("--exclude", "excludes", multiple=True, help="Glob of files to skip.")
@click.option("--ruleset", "ruleset_path", default=None, help="Path to a ruleset; defaults to the bundled published one.")
def scan_repo_cmd(repo_path, name, excludes, ruleset_path):
    """Scan one repository where it lives (e.g. in its CI). Writes a fragment with no code in it."""
    name = name or Path(repo_path).resolve().name
    ruleset, rdigest = load_ruleset(ruleset_path)
    frag, private = scan_repo(Path(repo_path), name, ruleset, rdigest, list(excludes))
    fpath, ppath = _write_repo_outputs(Path(repo_path), frag, private)
    r = frag["repo"]
    click.echo(f"Scanned {name}: {r['files_scanned']} files at {r['commit'][:12] if r['commit'] else 'no commit'}"
               f"{' (uncommitted changes)' if r['dirty'] else ''}.")
    click.echo("  " + "  ".join(f"{qid}: {q['count']}" for qid, q in frag["questions"].items()) + " evidence item(s)")
    click.echo(f"Fragment (findings, paths and fingerprints, no code): {fpath}")
    click.echo(f"Private evidence with snippets stays here: {ppath}")


@main.command()
@workspace_option
@click.option("--ruleset", "ruleset_path", default=None, help="Path to a ruleset; defaults to the bundled published one.")
@click.option("--model", default=None, help="Optional model id for a model review of the drafts (sends snippets to that provider).")
def scan(ws, ruleset_path, model):
    """Scan or collect every in-scope repository and draft company-wide answers."""
    wsp = Path(ws).resolve()
    d = _dir(ws)
    cfg = _cfg(ws)
    ruleset, rdigest = load_ruleset(ruleset_path)
    entries = _entries(cfg)
    if not any(e.get("in_scope", True) for e in entries):
        raise click.ClickException("no repositories in scope; add one with `privacy-attest repo add`")

    fragments, inventory, private_paths = [], [], {}
    for e in entries:
        if not e.get("in_scope", True):
            inventory.append({"name": e["name"], "in_scope": False, "reason": e["reason"]})
            continue
        if "path" in e:
            root = (wsp / e["path"]).resolve()
            if not root.is_dir():
                raise click.ClickException(f"{e['name']}: {root} is not a folder")
            frag, private = scan_repo(root, e["name"], ruleset, rdigest, cfg.get("exclude", []) + e.get("exclude", []))
            _, ppath = _write_repo_outputs(root, frag, private)
            source = "scanned here"
        else:
            fpath = (wsp / e["fragment"]).resolve()
            frag = _load(fpath)
            if frag.get("type") != FRAGMENT_TYPE:
                raise click.ClickException(f"{fpath} is not a privacy-attest fragment of this version")
            if frag["repo"]["name"] != e["name"]:
                raise click.ClickException(f"{fpath} is for repository '{frag['repo']['name']}', not '{e['name']}'")
            if frag["ruleset"]["digest"] != rdigest:
                raise click.ClickException(f"{e['name']} was scanned with a different ruleset; rescan it")
            ppath = fpath.parent / "evidence.private.json"
            ppath = ppath if ppath.exists() else None
            source = "fragment"
        fragments.append(frag)
        private_paths[e["name"]] = str(ppath) if ppath else None
        r = frag["repo"]
        inventory.append({
            "name": e["name"], "in_scope": True, "source": source, "commit": r["commit"], "dirty": r["dirty"],
            "files_scanned": r["files_scanned"], "tree_digest": r["tree_digest"], "scanned_at": frag["scanned_at"],
            "agent_version": frag["agent"]["version"], "agent_digest": frag["agent"]["digest"],
        })

    drafts = decide(ruleset, fragments, cfg)
    _write(d / "evidence-index.json",
           {"repos": private_paths, "questions": {dr.qid: dr.evidence for dr in drafts}})
    if model:
        from .llm import review
        snippets = {}
        for p in private_paths.values():
            snippets.update(_snippets(p))
        drafts = copy.deepcopy(drafts)
        for dr in drafts:
            for f in dr.evidence:
                f["snippet"] = snippets.get(f["fingerprint"])
        drafts = review(drafts, model)
    doc = answers_doc(drafts, inventory, cfg, ruleset, rdigest, agent_digest(), model or "rules-only")
    _write(d / "answers.json", doc)

    in_scope = [r for r in inventory if r["in_scope"]]
    multi = len(inventory) > 1
    if multi:
        click.echo(f"{len(in_scope)} repositor{'y' if len(in_scope) == 1 else 'ies'} in scope, "
                   f"{len(inventory) - len(in_scope)} out of scope.")
        for r in inventory:
            if r["in_scope"]:
                c = r["commit"][:12] if r["commit"] else "no commit"
                click.echo(f"  {r['name']:18} {r['source']:13} {c}  {r['files_scanned']} files"
                           f"{'  (uncommitted changes)' if r['dirty'] else ''}")
            else:
                click.echo(f"  {r['name']:18} out of scope  {r['reason']}")
        click.echo("")
    else:
        r = in_scope[0]
        click.echo(f"Scanned {r['files_scanned']} files at {r['commit'][:12] if r['commit'] else 'no commit'}"
                   f"{' (uncommitted changes)' if r['dirty'] else ''}.\n")
    for a in doc["answers"]:
        click.echo(f"{a['id']}  {_wrap(a['agent_answer'], 48):48}  {a['confidence']:6}  {a['evidence_count']:>3} evidence")
        click.echo(f"     {a['rationale']}")
        if len(in_scope) > 1:
            click.echo("     from " + ", ".join(f"{b['repo']} {b['count']}" for b in a["evidence_by_repo"]))
    click.echo("\nReview .attest/answers.json. Change any answer with `privacy-attest override`, then `privacy-attest sign`.")


@main.command()
@click.argument("qid")
@workspace_option
def evidence(qid, ws):
    """Show the evidence behind one answer (never sent to the reviewer)."""
    idx = _load(_dir(ws) / "evidence-index.json")
    facts = idx["questions"].get(qid, [])
    multi = len(idx["repos"]) > 1
    cache: dict[str, dict] = {}
    for i, f in enumerate(facts):
        repo = f["repo"]
        if repo not in cache:
            cache[repo] = _snippets(idx["repos"].get(repo))
        where = f"{repo}/{f['path']}:{f['line']}" if multi else f"{f['path']}:{f['line']}"
        click.echo(f"[{i}] {f['signal']:16} {where}  {f['note']}")
        snippet = cache[repo].get(f["fingerprint"])
        click.echo(f"     {snippet}" if snippet is not None else f"     (snippet held with {repo}; not on this machine)")
    if not facts:
        click.echo("No evidence for this question.")


@main.command()
@click.argument("qid")
@click.option("--answer", required=True)
@click.option("--reason", required=True, help="Why you disagree with the agent. Sent to the reviewer.")
@workspace_option
def override(qid, answer, reason, ws):
    """Replace the agent's answer. The original answer and your reason are both attested."""
    p = _dir(ws) / "answers.json"
    try:
        doc = apply_override(_load(p), qid, answer, reason)
    except (ValueError, KeyError) as exc:
        raise click.ClickException(str(exc))
    _write(p, doc)
    click.echo(f"{qid} now answered '{answer}'. The agent's answer and your reason will both be visible to the reviewer.")


@main.command()
@workspace_option
@click.option("-o", "--out", default="submission.json", show_default=True)
def sign(ws, out):
    """Sign the answers and repository inventory as an in-toto statement in a DSSE envelope."""
    d = _dir(ws)
    env = sign_doc(_load(d / "answers.json"), d / "member_key.pem", d / "member_key.pub.pem")
    _write(Path(out), env)
    click.echo(f"Signed submission written to {out}. It contains answers, override reasons, the repository "
               f"inventory and evidence fingerprints, no code.")


@main.command()
@click.argument("qid")
@click.option("--item", "index", type=int, required=True, help="Evidence index from `privacy-attest evidence`.")
@click.option("--evidence", "evidence_path", default=None,
              help="That repository's evidence.private.json, if it is not where the scan left it.")
@workspace_option
@click.option("-o", "--out", default=None)
def reveal(qid, index, evidence_path, ws, out):
    """For a spot check: reveal one evidence item with a proof it was in the signed submission."""
    d = _dir(ws)
    idx = _load(d / "evidence-index.json")
    facts = idx["questions"].get(qid, [])
    if not 0 <= index < len(facts):
        raise click.ClickException(f"{qid} has {len(facts)} evidence item(s)")
    fact = facts[index]
    repo = fact["repo"]
    local = sum(1 for f in facts[:index] if f["repo"] == repo)
    ppath = evidence_path or idx["repos"].get(repo)
    if not ppath or not Path(ppath).exists():
        raise click.ClickException(f"{repo}'s private evidence is not on this machine; "
                                   f"pass --evidence with its evidence.private.json")
    items = _load(Path(ppath)).get(qid, [])
    try:
        r = make_reveal(_load(d / "answers.json"), items, qid, repo, local)
    except (IndexError, KeyError, ValueError) as exc:
        raise click.ClickException(str(exc))
    out = out or f"reveal-{qid}-{index}.json"
    _write(Path(out), r)
    click.echo(f"{repo}/{r['item']['path']}:{r['item']['line']}\n  {r['item']['snippet']}\nWritten to {out}.")


# ---------------------------------------------------------------- Reviewer side

@main.command()
@click.argument("submission", type=click.Path(exists=True))
@click.option("--member-key", required=True, type=click.Path(exists=True), help="Member's registered public key.")
@click.option("--ruleset", "ruleset_path", default=None, help="Published ruleset; defaults to the bundled one.")
@click.option("--agent-digest", multiple=True, help="Released agent build digests the reviewer accepts.")
def verify(submission, member_key, ruleset_path, agent_digest):
    """Reviewer side: check signature, ruleset and agent builds, then show inventory, answers and overrides."""
    if ruleset_path:
        rdigest = ruleset_digest_of(Path(ruleset_path))
    else:
        _, rdigest = load_ruleset(None)
    try:
        st, warnings = verify_env(json.loads(Path(submission).read_text(encoding="utf-8")), Path(member_key),
                                  rdigest, list(agent_digest) or None)
    except VerificationError as exc:
        click.echo(f"FAILED: {exc}")
        sys.exit(1)
    p = st["predicate"]
    s = p["scan"]
    click.echo(f"VERIFIED  {p['member']}  signed {p['signedAt']}")
    click.echo(f"  agent {p['agent']['name']} {p['agent']['version']} ({p['agent']['model']}), "
               f"ruleset {p['ruleset']['version']}, {s['reposInScope']} repo(s) in scope, {s['filesScanned']} files")
    click.echo("  inventory:")
    for r in p["inventory"]:
        if r["inScope"]:
            c = r["commit"][:12] if r["commit"] else "no commit"
            click.echo(f"    in scope      {r['name']:18} {c}  {r['filesScanned']} files, {r['source']}, scanned {r['scannedAt']}")
        else:
            click.echo(f"    out of scope  {r['name']:18} {r['reason']}")
    for w in warnings:
        click.echo(f"  WARNING: {w}")
    click.echo("")
    multi = s["reposInScope"] > 1
    for a in p["answers"]:
        flag = "OVERRIDDEN" if a["overridden"] else "          "
        click.echo(f"{a['id']}  {flag}  {_wrap(a['finalAnswer'], 52)}")
        click.echo(f"     agent's reasoning: {a['rationale']}")
        if a["overridden"]:
            click.echo(f"     agent said: {a['agentAnswer']}")
            click.echo(f"     member's reason: {a['overrideReason']}")
        ev = a["evidence"]
        frm = (" from " + ", ".join(f"{b['repo']} {b['count']}" for b in ev["byRepo"])) if multi else ""
        click.echo(f"     {ev['count']} evidence item(s){frm}, root {ev['merkleRoot'][:16]}…")


@main.command("check-reveal")
@click.argument("submission", type=click.Path(exists=True))
@click.argument("reveal_file", type=click.Path(exists=True))
@click.option("--member-key", required=True, type=click.Path(exists=True))
def check_reveal_cmd(submission, reveal_file, member_key):
    """Reviewer side: confirm a revealed snippet was part of the signed evidence, for that repository and commit."""
    _, rdigest = load_ruleset(None)
    try:
        st, _ = verify_env(json.loads(Path(submission).read_text(encoding="utf-8")), Path(member_key), rdigest)
    except VerificationError as exc:
        click.echo(f"FAILED: {exc}")
        sys.exit(1)
    r = json.loads(Path(reveal_file).read_text(encoding="utf-8"))
    ok, why = check_reveal(st, r)
    if ok:
        click.echo(f"MATCH: {r['repo']}/{r['item']['path']}:{r['item']['line']} at commit {(r['commit'] or 'none')[:12]} "
                   f"was in the evidence signed for {r['question']}.")
    else:
        click.echo(f"NO MATCH: {why}.")
        sys.exit(1)


if __name__ == "__main__":
    main()
