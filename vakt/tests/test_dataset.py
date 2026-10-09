import json
from pathlib import Path

from vakt.builders import attack_examples, clean
from vakt.split import split_of


def test_split_is_deterministic_and_covers_all():
    assert split_of("attack:T1059") == split_of("attack:T1059")
    assert {split_of(f"x{i}") for i in range(500)} == {"train", "val", "test"}


def test_clean_strips_citations_and_links():
    assert clean("Se [dok](http://x) (Citation: Foo) nå") == "Se dok  nå"


def test_attack_examples_skip_revoked_and_format(tmp_path: Path):
    def tech(tid, **kw):
        return {"type": "attack-pattern", "name": f"N{tid}", "description": "d" * 10,
                "external_references": [{"source_name": "mitre-attack", "external_id": tid}],
                "kill_chain_phases": [{"phase_name": "execution"}], **kw}
    data = {"objects": [tech("T1"), tech("T2", revoked=True), tech("T3", x_mitre_detection="Overvåk X")]}
    p = tmp_path / "a.json"
    p.write_text(json.dumps(data))
    ids = [e["id"] for e in attack_examples(p)]
    assert ids == ["attack:T1", "attack:T3", "attack:T3:detect"]
    ex = attack_examples(p)[0]
    assert [m["role"] for m in ex["messages"]] == ["system", "user", "assistant"]
    assert "Kilde: MITRE ATT&CK T1" in ex["messages"][2]["content"]
