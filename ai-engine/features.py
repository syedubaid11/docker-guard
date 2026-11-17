"""Turns raw CVE fields into the table the model reads.

Shared by train.py and (later) the API, so training and live scans build features the same way.
Self-check: python features.py
"""
import pandas as pd

# The eight parts of a CVSS v3 vector, e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
CVSS_KEYS = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]


def to_frame(records, now):
    """records: dicts with id, vector, score, cwes, published, description. now: UTC pd.Timestamp."""
    df = pd.DataFrame(records)
    parts = df["vector"].fillna("").map(lambda v: dict(p.split(":", 1) for p in v.split("/") if ":" in p))
    for key in CVSS_KEYS:
        df[key] = parts.map(lambda p: p.get(key, "?"))
    df["cvss_score"] = df["score"].astype(float)
    # NVD also lists placeholders like "NVD-CWE-noinfo"; keep the first real CWE.
    df["cwe"] = df["cwes"].map(lambda c: next((x for x in c if x.startswith("CWE-")), "none"))
    df["published"] = pd.to_datetime(df["published"], utc=True)
    df["age_days"] = (now - df["published"]).dt.days
    df["description"] = df["description"].fillna("")
    return df


if __name__ == "__main__":
    row = to_frame(
        [{
            "id": "CVE-2021-44228",
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "score": 10.0,
            "cwes": ["NVD-CWE-noinfo", "CWE-502"],
            "published": "2021-12-10T10:15:00Z",
            "description": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP endpoints.",
        }],
        pd.Timestamp("2026-01-01", tz="UTC"),
    ).iloc[0]
    assert (row["AV"], row["PR"], row["S"]) == ("N", "N", "C"), row
    assert row["cwe"] == "CWE-502", row["cwe"]
    assert row["age_days"] == 1482, row["age_days"]
    print("features.py ok")
