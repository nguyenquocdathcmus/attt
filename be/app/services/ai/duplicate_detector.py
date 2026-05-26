import re


def _normalize_title(title: str) -> str:
    """Strip numbers and URLs to get a canonical vulnerability class key."""
    t = title.lower()
    t = re.sub(r"https?://\S+", "", t)
    t = re.sub(r"\d+", "", t)
    t = re.sub(r"[^a-z\s]", " ", t)
    t = re.sub(r"\s+", "_", t.strip())
    return t[:50]


def _group_key(finding: dict) -> str:
    """
    Stable group key based on CWE + normalized title.
    Findings that share a CWE and describe the same vulnerability class
    will land in the same group regardless of affected URL or parameter.
    """
    cwe = (finding.get("cwe") or "unknown").replace("-", "_").lower()
    title_slug = _normalize_title(finding.get("title", "unknown"))
    return f"{cwe}__{title_slug}"


def detect(findings: list[dict]) -> list[dict]:
    """
    Assign duplicate_group to each finding.

    Findings in the same group share a root cause (same CWE + vulnerability class).
    The group key is deterministic so the same vulnerability found across multiple
    URLs will be clustered together.
    """
    group_counts: dict[str, int] = {}

    for f in findings:
        key = _group_key(f)
        f["duplicate_group"] = key
        group_counts[key] = group_counts.get(key, 0) + 1

    # Tag findings that are part of a duplicate cluster
    for f in findings:
        key = f["duplicate_group"]
        if group_counts[key] > 1:
            # Append count hint so consumers know this is a cluster
            f["duplicate_group"] = f"{key}[{group_counts[key]}]"

    return findings
