"""Deterministisk train/val/test-splitt per kilde-ID, slik at samme kilde aldri havner i to sett."""
import hashlib


def split_of(source_id: str) -> str:
    bucket = int(hashlib.sha256(source_id.encode()).hexdigest(), 16) % 100
    if bucket < 90:
        return "train"
    if bucket < 95:
        return "val"
    return "test"
