"""Optional model review of the rule-based drafts.

Off by default. When a member turns it on, the agent sends each question and
its evidence snippets to the model the member has chosen, and the model may
refine the answer and rationale. Snippets leave the member's environment only
to that model provider, never to the reviewer. The model id is recorded in the
attestation so the reviewer knows a model was involved.

Prototype: supports the Anthropic Messages API via ANTHROPIC_API_KEY. A member
could swap in any approved provider or a local model.
"""
from __future__ import annotations

import json
import os
import urllib.request

from .scan import Draft

PROMPT = """You are helping a company answer a privacy self-regulation questionnaire about its own code.
Question: {question}
A rule-based scan answered: {answer} (confidence {confidence}). Its reasoning: {rationale}
Evidence from the company's code (path:line: snippet), with the scanner's notes:
{evidence}

Using only this evidence, give the best answer. If the evidence is insufficient, say "Needs human input".
Reply with JSON only: {{"answer": "...", "confidence": "low|medium|high", "rationale": "one or two sentences citing path:line"}}"""


def review(drafts: list[Draft], model: str, max_items: int = 25) -> list[Draft]:
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise RuntimeError("ANTHROPIC_API_KEY is not set; run without --model for rules-only answers")
    for d in drafts:
        ev = "\n".join(
            f"{e['repo']}/{e['path']}:{e['line']}: {e.get('snippet') or '(snippet not available on this machine)'}"
            f"  [{e['signal']}{'; ' + e['note'] if e['note'] else ''}]"
            for e in d.evidence[:max_items]) or "(none)"
        body = {
            "model": model,
            "max_tokens": 400,
            "messages": [{"role": "user", "content": PROMPT.format(
                question=d.text, answer=d.answer, confidence=d.confidence,
                rationale=d.rationale, evidence=ev)}],
        }
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=json.dumps(body).encode(),
            headers={"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=60) as r:
            text = json.loads(r.read())["content"][0]["text"]
        try:
            out = json.loads(text[text.index("{"): text.rindex("}") + 1])
        except ValueError:
            continue  # keep the rule-based draft if the model reply can't be parsed
        d.answer = out.get("answer", d.answer)
        d.confidence = out.get("confidence", d.confidence)
        d.rationale = out.get("rationale", d.rationale) + " [model-reviewed]"
    return drafts
