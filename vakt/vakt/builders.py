"""Bygger chat-eksempler (system/user/assistant) fra ATT&CK, OWASP og Sigma."""
import json
import re
from pathlib import Path

import yaml

from .persona import SYSTEM_PROMPT

MAX_CHARS = 1800


def example(source_id: str, source: str, user: str, assistant: str) -> dict:
    return {
        "id": source_id,
        "source": source,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user},
            {"role": "assistant", "content": assistant},
        ],
    }


def clean(text: str) -> str:
    text = re.sub(r"\(Citation:[^)]*\)", "", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"<[^>]+>", "", text)
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def clip(text: str, n: int = MAX_CHARS) -> str:
    return text if len(text) <= n else text[:n].rsplit(" ", 1)[0] + " ..."


def attack_examples(path: Path) -> list[dict]:
    objects = json.loads(path.read_text(encoding="utf-8"))["objects"]
    out = []
    for o in objects:
        if o.get("type") != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        refs = [r for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"]
        if not refs:
            continue
        tid, name = refs[0]["external_id"], o["name"]
        tactics = ", ".join(p["phase_name"] for p in o.get("kill_chain_phases", [])) or "ukjent"
        platforms = ", ".join(o.get("x_mitre_platforms", [])) or "ukjent"
        desc = clip(clean(o.get("description", "")))
        sid = f"attack:{tid}"
        out.append(example(
            sid, "attack",
            f"Hva er MITRE ATT&CK {tid}?",
            f"{tid} er «{name}». Taktikk: {tactics}. Plattformer: {platforms}.\n\n{desc}\n\nKilde: MITRE ATT&CK {tid}",
        ))
        det = clean(o.get("x_mitre_detection", ""))
        if det:
            out.append(example(
                sid + ":detect", "attack",
                f"Hvordan kan jeg oppdage {name} ({tid})?",
                f"Deteksjon for {tid} ({name}):\n\n{clip(det)}\n\nKilde: MITRE ATT&CK {tid}",
            ))
    return out


def owasp_examples(root: Path) -> list[dict]:
    out = []
    for md in sorted((root / "cheatsheets").glob("*.md")):
        text = md.read_text(encoding="utf-8")
        title_m = re.search(r"^#\s+(.+)$", text, re.M)
        title = title_m.group(1).strip() if title_m else md.stem
        parts = re.split(r"^##\s+(.+)$", text, flags=re.M)
        for heading, body in zip(parts[1::2], parts[2::2]):
            body = clean(body)
            if len(body) < 200 or heading.strip().lower() in {"introduction", "references"}:
                continue
            sid = f"owasp:{md.stem}:{heading.strip().lower()}"
            out.append(example(
                sid, "owasp",
                f"Hva anbefaler OWASP om «{heading.strip()}» i {title}?",
                f"{clip(body)}\n\nKilde: OWASP Cheat Sheet Series, {title}",
            ))
    return out


def sigma_examples(root: Path) -> list[dict]:
    out = []
    for yml in sorted((root / "rules").rglob("*.yml")):
        raw = yml.read_text(encoding="utf-8")
        try:
            rule = yaml.safe_load(raw)
        except yaml.YAMLError:
            continue
        if not isinstance(rule, dict) or not all(k in rule for k in ("title", "description", "detection")):
            continue
        if len(raw) > 3000 or rule.get("status") == "deprecated":
            continue
        ttps = [t[7:].upper() for t in rule.get("tags", []) if isinstance(t, str) and re.match(r"attack\.t\d", t)]
        sid = f"sigma:{rule.get('id', yml.stem)}"
        ttp_note = f" Dekker MITRE ATT&CK {', '.join(ttps)}." if ttps else ""
        out.append(example(
            sid, "sigma",
            f"Skriv en Sigma-regel som oppdager: {str(rule['description']).strip()}",
            f"```yaml\n{raw.strip()}\n```\n\nKilde: SigmaHQ, regel «{rule['title']}».{ttp_note}",
        ))
    return out
