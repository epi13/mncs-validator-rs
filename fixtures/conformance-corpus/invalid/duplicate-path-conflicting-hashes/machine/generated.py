# MNCS-GENERATED: DO NOT EDIT
# Table-driven example; this does not claim the validator is machine-native.

_RANK = {"PASS": 0, "UNKNOWN": 1, "FAIL": 2}

def aggregate(statuses: list[str]) -> str:
    return max(statuses, key=_RANK.__getitem__) if statuses else "UNKNOWN"
