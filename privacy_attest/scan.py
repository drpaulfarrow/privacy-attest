"""Scan member repositories and draft answers to the ruleset questions.

Members rarely keep everything in one repository: the tag, the bidder, the
audience pipeline and the infrastructure usually live apart, often with
different teams and different CI. So scanning has two stages:

  scan_repo  runs inside one repository, wherever it lives (a laptop, or that
             repository's own CI). It collects evidence for every question and
             returns a fragment (findings, paths and fingerprints, no code) and
             the private evidence (with snippets). Both stay with the member.
  decide     runs over the fragments of every in-scope repository and drafts
             company-wide answers. A GPC gap in any repository makes Q1
             "Partially"; Q5 lists recipients from all of them; and so on.

Only fingerprints of the evidence ever reach the reviewer.
"""
from __future__ import annotations

import fnmatch
import re
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path

import yaml

from . import AGENT_NAME, FRAGMENT_TYPE, __version__
from .crypto import leaf_hash, merkle_root, sha256_hex

TEXT_SUFFIXES = {
    ".js", ".mjs", ".ts", ".tsx", ".jsx", ".py", ".go", ".java", ".kt", ".rb", ".php",
    ".cs", ".scala", ".rs", ".swift", ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg",
    ".conf", ".csv", ".sql", ".html", ".tf", ".env.example",
}
DEFAULT_EXCLUDES = [".git/*", ".attest/*", "node_modules/*", "vendor/*", "dist/*", "build/*", "*.min.js"]


def now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


# ---------------------------------------------------------------- ruleset

def load_ruleset(path: Path | None = None) -> tuple[dict, str]:
    if path is None:
        raw = resources.files("privacy_attest").joinpath("ruleset/privacy-ruleset-v0.1.yaml").read_bytes()
    else:
        raw = Path(path).read_bytes()
    return yaml.safe_load(raw), sha256_hex(raw)


def agent_digest() -> str:
    """Digest of the agent's own source, so the reviewer can check which build ran."""
    pkg = resources.files("privacy_attest")
    parts = []
    for name in sorted(p.name for p in pkg.iterdir() if p.name.endswith(".py")):
        parts.append(name.encode() + b"\0" + pkg.joinpath(name).read_bytes())
    return sha256_hex(b"\n".join(parts))


# ---------------------------------------------------------------- repo

@dataclass
class RepoInfo:
    root: str
    commit: str | None
    dirty: bool
    files: list[str]
    tree_digest: str


def repo_info(root: Path, excludes: list[str]) -> RepoInfo:
    root = root.resolve()
    commit, dirty, files = None, False, None
    try:
        commit = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                                capture_output=True, text=True, check=True).stdout.strip()
        dirty = bool(subprocess.run(["git", "-C", str(root), "status", "--porcelain"],
                                    capture_output=True, text=True, check=True).stdout.strip())
        files = subprocess.run(["git", "-C", str(root), "ls-files"],
                               capture_output=True, text=True, check=True).stdout.splitlines()
    except (subprocess.CalledProcessError, FileNotFoundError):
        files = [p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()]
    keep = []
    for f in sorted(files):
        if any(fnmatch.fnmatch(f, pat) for pat in excludes):
            continue
        p = root / f
        if p.is_file() and (p.suffix in TEXT_SUFFIXES or p.name.endswith(".env.example")):
            keep.append(f)
    # Tree digest: what exactly was scanned, file by file.
    lines = [f"{sha256_hex((root / f).read_bytes())}  {f}" for f in keep]
    return RepoInfo(str(root), commit, dirty, keep, sha256_hex("\n".join(lines)))


# ---------------------------------------------------------------- evidence

@dataclass
class Evidence:
    repo: str
    qid: str
    signal: str
    path: str
    line: int
    snippet: str
    note: str = ""

    @property
    def fingerprint(self) -> str:
        # Binds the claim to exact bytes, and to the repository, without revealing them.
        return leaf_hash(f"pa-evidence|{self.repo}|{self.qid}|{self.signal}|{self.path}|{self.line}|{self.snippet}")

    def fact(self) -> dict:
        """What the fragment carries: everything except the snippet."""
        return {"repo": self.repo, "signal": self.signal, "path": self.path, "line": self.line,
                "note": self.note, "fingerprint": self.fingerprint}


def repo_leaf(name: str, commit: str | None, root: str) -> str:
    """Leaf of a question's top-level tree: one per repository, bound to its commit."""
    return leaf_hash(f"pa-repo|{name}|{commit or ''}|{root}")


@dataclass
class Draft:
    qid: str
    key: str
    text: str
    answer: str
    confidence: str
    rationale: str
    evidence: list[dict] = field(default_factory=list)   # facts across repos, no snippets
    by_repo: list[dict] = field(default_factory=list)    # [{"repo", "count", "root"}]
    evidence_root: str = ""


def _read_lines(root: Path, rel: str) -> list[str]:
    try:
        return (root / rel).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def _grep(root: Path, files: list[str], pattern: str):
    rx = re.compile(pattern)
    for rel in files:
        for n, line in enumerate(_read_lines(root, rel), start=1):
            m = rx.search(line)
            if m:
                yield rel, n, line.strip()[:240], m


# ---------------------------------------------------------------- collectors (per repository)

def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


def _inside_gate(lines: list[str], n: int, gate: re.Pattern, win: int) -> bool:
    """Is line n (1-based) inside an `if` block whose condition is an opt-out check?

    Heuristic for the prototype: braces for C-style code, indentation for Python.
    A production agent would use a parser or a model for this step.
    """
    call = lines[n - 1]
    if gate.search(call):
        return True
    for k in range(n - 2, max(-1, n - 2 - win), -1):
        cond = lines[k]
        if not gate.search(cond):
            continue
        between = lines[k:n - 1]
        if "{" in cond:
            depth, closed = 0, False
            for l in between:
                depth += l.count("{") - l.count("}")
                if depth <= 0:
                    closed = True
                    break
            if not closed:
                return True
        elif cond.rstrip().endswith(":"):
            base = _indent(cond)
            if _indent(call) > base and all(_indent(l) > base or not l.strip() for l in lines[k + 1:n - 1]):
                return True
    return False


def co_gpc_gating(q, root, files, repo):
    s = q["signals"]
    win = int(q.get("gate_window_lines", 12))
    gate = re.compile(s["gate_hint"])
    ev = [Evidence(repo, q["id"], "gpc_read", p, n, t) for p, n, t, _ in _grep(root, files, s["gpc_read"])]
    for p, n, t, _ in _grep(root, files, s["third_party_call"]):
        gated = _inside_gate(_read_lines(root, p), n, gate, win)
        ev.append(Evidence(repo, q["id"], "third_party_call", p, n, t,
                           "gated" if gated else "not gated by an opt-out check"))
    return ev, {}


def co_precise_geo(q, root, files, repo):
    s = q["signals"]
    ev = []
    for signal in ("browser_geo", "coordinates", "coarsening"):
        ev += [Evidence(repo, q["id"], signal, p, n, t) for p, n, t, _ in _grep(root, files, s[signal])]
    return ev, {}


def co_sensitive_segments(q, root, files, repo):
    hint = re.compile(q["path_hint"])
    seg_files = [f for f in files if hint.search(f)]
    ev = [Evidence(repo, q["id"], "sensitive_term", p, n, t)
          for p, n, t, _ in _grep(root, seg_files, q["signals"]["sensitive_term"])]
    return ev, {"segment_files": len(seg_files)}


def co_retention(q, root, files, repo):
    ev = [Evidence(repo, q["id"], "retention", p, n, t, f"{int(m.group(2))} days")
          for p, n, t, m in _grep(root, files, q["signals"]["retention"])]
    return ev, {}


def co_recipients(q, root, files, repo):
    found: dict[str, Evidence] = {}
    for p, n, t, _ in _grep(root, files, q["signals"]["url"]):
        for m in re.finditer(q["signals"]["url"], t):
            host = m.group(1).lower()
            found.setdefault(host, Evidence(repo, q["id"], "url", p, n, t, host))
    return list(found.values()), {}


# ---------------------------------------------------------------- deciders (company-wide)

def de_gpc_gating(q, facts, metas, cfg, loc):
    reads = [f for f in facts if f["signal"] == "gpc_read"]
    calls = [f for f in facts if f["signal"] == "third_party_call"]
    ungated = [f for f in calls if f["note"] != "gated"]
    if not reads:
        return "No", "high" if calls else "medium", \
            f"No code reads the GPC signal. Found {len(calls)} third-party call(s)."
    if not calls:
        return "Yes", "low", "GPC is read but no third-party calls were found to gate; check scope."
    if not ungated:
        return "Yes", "medium", f"GPC is read and all {len(calls)} third-party call(s) sit behind an opt-out check."
    where = "; ".join(loc(f) for f in ungated[:5])
    return "Partially", "medium", \
        f"GPC is read, but {len(ungated)} of {len(calls)} third-party call(s) are not behind an opt-out check ({where})."


def de_precise_geo(q, facts, metas, cfg, loc):
    browser = [f for f in facts if f["signal"] == "browser_geo"]
    coords = [f for f in facts if f["signal"] == "coordinates"]
    coarse = [f for f in facts if f["signal"] == "coarsening"]
    if browser:
        return "Yes", "high", f"Browser geolocation API is called ({len(browser)} place(s): {', '.join(loc(f) for f in browser[:3])})."
    if coords and not coarse:
        return "Yes", "medium", f"Latitude/longitude handled in {len(coords)} place(s) with no coarsening found."
    if coords and coarse:
        return "Coarse only", "medium", "Coordinates are handled and coarsened before use; confirm every path coarsens."
    return "No", "medium", "No geolocation APIs or coordinate fields found."


def de_sensitive_segments(q, facts, metas, cfg, loc):
    seg_files = sum(m.get("segment_files", 0) for m in metas)
    if not seg_files:
        return "Unknown", "low", "No segment or taxonomy files found in scope."
    if facts:
        n_files = len({(f["repo"], f["path"]) for f in facts})
        return "Yes", "medium", \
            f"{len(facts)} segment definition(s) match sensitive categories in {n_files} file(s) ({', '.join(loc(f) for f in facts[:3])})."
    return "No", "medium", f"Checked {seg_files} segment file(s); no sensitive categories found."


def de_retention(q, facts, metas, cfg, loc):
    if not facts:
        return "No limit found", "medium", "No retention or TTL settings found for event data."
    days = [int(f["note"].split()[0]) for f in facts]
    longest = facts[days.index(max(days))]
    return f"Yes, longest {max(days)} days", "medium", \
        f"{len(days)} retention setting(s) found, from {min(days)} to {max(days)} days (longest at {loc(longest)})."


def de_recipients(q, facts, metas, cfg, loc):
    own = [d.lower() for d in cfg.get("first_party_domains", []) + cfg.get("ignore_domains", [])]
    hosts = sorted({f["note"] for f in facts
                    if not any(f["note"] == d or f["note"].endswith("." + d) for d in own)})
    if not hosts:
        return "None found", "low", "No external endpoints found in scope."
    return ", ".join(hosts), "medium", f"{len(hosts)} external endpoint(s) referenced in code or config."


EVALUATORS = {
    "gpc_gating": (co_gpc_gating, de_gpc_gating),
    "precise_geo": (co_precise_geo, de_precise_geo),
    "sensitive_segments": (co_sensitive_segments, de_sensitive_segments),
    "retention": (co_retention, de_retention),
    "recipients": (co_recipients, de_recipients),
}


# ---------------------------------------------------------------- stage 1: one repository

def scan_repo(root: Path, name: str, ruleset: dict, ruleset_digest: str,
              excludes: list[str] | None = None) -> tuple[dict, dict]:
    """Scan one repository. Returns (fragment, private evidence)."""
    info = repo_info(Path(root), DEFAULT_EXCLUDES + list(excludes or []))
    questions, private = {}, {}
    for q in ruleset["questions"]:
        collect, _ = EVALUATORS[q["evaluator"]]
        ev, meta = collect(q, Path(info.root), info.files, name)
        questions[q["id"]] = {
            "count": len(ev),
            "root": merkle_root([e.fingerprint for e in ev]),
            "meta": meta,
            "facts": [e.fact() for e in ev],
        }
        private[q["id"]] = [dict(asdict(e), fingerprint=e.fingerprint) for e in ev]
    fragment = {
        "type": FRAGMENT_TYPE,
        "repo": {"name": name, "commit": info.commit, "dirty": info.dirty,
                 "files_scanned": len(info.files), "tree_digest": info.tree_digest},
        "scanned_at": now(),
        "agent": {"name": AGENT_NAME, "version": __version__, "digest": agent_digest()},
        "ruleset": {"version": ruleset["version"], "digest": ruleset_digest},
        "questions": questions,
    }
    return fragment, private


# ---------------------------------------------------------------- stage 2: all repositories

def decide(ruleset: dict, fragments: list[dict], cfg: dict) -> list[Draft]:
    """Draft company-wide answers from the fragments of every in-scope repository."""
    multi = len(fragments) > 1

    def loc(f: dict) -> str:
        return f"{f['repo']}/{f['path']}:{f['line']}" if multi else f"{f['path']}:{f['line']}"

    drafts = []
    for q in ruleset["questions"]:
        _, judge = EVALUATORS[q["evaluator"]]
        parts = [fr["questions"][q["id"]] for fr in fragments]
        facts = [dict(f) for p in parts for f in p["facts"]]
        answer, conf, why = judge(q, facts, [p["meta"] for p in parts], cfg, loc)
        by_repo = [{"repo": fr["repo"]["name"], "count": p["count"], "root": p["root"]}
                   for fr, p in zip(fragments, parts)]
        root = merkle_root([repo_leaf(fr["repo"]["name"], fr["repo"]["commit"], p["root"])
                            for fr, p in zip(fragments, parts)])
        drafts.append(Draft(q["id"], q["key"], " ".join(q["text"].split()), answer, conf, why,
                            facts, by_repo, root))
    return drafts
