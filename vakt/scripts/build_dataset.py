"""Bygger data/processed/{train,val,test}.jsonl fra data/raw. Kjør etter fetch_sources.py."""
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from vakt.builders import attack_examples, owasp_examples, sigma_examples  # noqa: E402
from vakt.split import split_of  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
RAW, OUT = ROOT / "data" / "raw", ROOT / "data" / "processed"


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    examples = (
        attack_examples(RAW / "enterprise-attack.json")
        + owasp_examples(RAW / "owasp")
        + sigma_examples(RAW / "sigma")
    )
    buckets: dict[str, list[dict]] = {"train": [], "val": [], "test": []}
    for ex in examples:
        # :detect-varianter følger grunn-IDen, slik at samme kilde ikke lekker mellom sett
        buckets[split_of(ex["id"].split(":detect")[0])].append(ex)
    for name, rows in buckets.items():
        with (OUT / f"{name}.jsonl").open("w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print({k: len(v) for k, v in buckets.items()}, dict(Counter(e["source"] for e in examples)))


if __name__ == "__main__":
    main()
