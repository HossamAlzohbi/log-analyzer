"""Henter åpne kilder til data/raw. Kjøres på din maskin: python scripts/fetch_sources.py"""
import subprocess
import urllib.request
from pathlib import Path

RAW = Path(__file__).resolve().parent.parent / "data" / "raw"
ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
REPOS = {
    "owasp": "https://github.com/OWASP/CheatSheetSeries.git",
    "sigma": "https://github.com/SigmaHQ/sigma.git",
}


def fetch_attack() -> None:
    dest = RAW / "enterprise-attack.json"
    if dest.exists():
        print(f"hopper over {dest.name} (finnes)")
        return
    print("laster ned MITRE ATT&CK ...")
    urllib.request.urlretrieve(ATTACK_URL, dest)


def clone(name: str, url: str) -> None:
    dest = RAW / name
    if dest.exists():
        print(f"hopper over {name} (finnes)")
        return
    print(f"kloner {name} ...")
    subprocess.run(["git", "clone", "--depth", "1", "-q", url, str(dest)], check=True)


def main() -> None:
    RAW.mkdir(parents=True, exist_ok=True)
    fetch_attack()
    for name, url in REPOS.items():
        clone(name, url)
    print("ferdig:", RAW)


if __name__ == "__main__":
    main()
