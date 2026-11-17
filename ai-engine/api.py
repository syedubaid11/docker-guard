"""DockerGuard AI engine: scores CVEs with the trained model and explains each score.

Run:        uvicorn api:app --port 8000
Self-check: python api.py   (needs out/model.joblib from train.py)
"""
from pathlib import Path

import joblib
import pandas as pd
import xgboost
from fastapi import FastAPI
from pydantic import BaseModel

from features import to_frame

bundle = joblib.load(Path(__file__).parent / "out" / "model.joblib")
PRE, MODEL = bundle["pre"], bundle["model"]
NAMES = PRE.get_feature_names_out()

# Plain-English text for the CVSS vector parts that make a CVE riskier.
CVSS_TEXT = {
    "AV_N": "Can be attacked over the network",
    "AV_A": "Can be attacked from the same local network",
    "AC_L": "Easy to exploit",
    "PR_N": "No login needed",
    "PR_L": "Only a basic user login needed",
    "UI_N": "No user action needed",
    "S_C": "Can spread beyond the vulnerable component",
    "C_H": "Can leak sensitive data",
    "I_H": "Can let attackers change data",
    "A_H": "Can crash the service",
}


def reason(name, row):
    """Turns one model feature (e.g. "cvss__AV_N") into a sentence, or None if it has no good wording."""
    group, value = name.split("__", 1)
    if group == "cvss":
        return CVSS_TEXT.get(value)
    if group == "cwe":
        cwe = value.removeprefix("cwe_")
        return f"Weakness type {cwe}" if cwe.startswith("CWE-") else None
    if name == "num__cvss_score":
        return f"CVSS score of {row.cvss_score}"
    if name == "num__age_days":
        return None if pd.isna(row.age_days) else f"Public for {int(row.age_days)} days"
    return f'Description mentions "{value}"'


class Cve(BaseModel):
    id: str
    vector: str | None = None
    score: float | None = None
    cwes: list[str] = []
    published: str | None = None
    description: str | None = None


app = FastAPI()


@app.post("/predict")
def predict(cves: list[Cve]):
    if not cves:
        return []
    df = to_frame([c.model_dump() for c in cves], pd.Timestamp.now(tz="UTC"))
    X = PRE.transform(df).tocsr()
    risk = MODEL.predict_proba(X)[:, 1]
    # SHAP values from XGBoost itself; the last column is the base value, not a feature.
    contribs = MODEL.get_booster().predict(xgboost.DMatrix(X), pred_contribs=True)[:, :-1]

    results = []
    for i, row in enumerate(df.itertuples()):
        # Only features this CVE actually has, that pushed its risk up, strongest first.
        pushing_up = sorted((c for c in X[i].indices if contribs[i, c] > 0), key=lambda c: -contribs[i, c])
        reasons = [text for c in pushing_up if (text := reason(NAMES[c], row))][:3]
        results.append({"id": row.id, "risk": round(float(risk[i]), 4), "reasons": reasons})
    return results


if __name__ == "__main__":
    log4shell, local_bug = predict([
        Cve(id="CVE-2021-44228", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", score=10.0,
            cwes=["CWE-502"], published="2021-12-10T10:15:00Z",
            description="Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other "
                        "JNDI related endpoints, allowing remote code execution."),
        Cve(id="CVE-TEST-LOCAL", vector="CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", score=1.8,
            cwes=["CWE-200"], published="2025-06-01T00:00:00Z",
            description="A local user with admin rights may read a minor log file."),
    ])
    print(log4shell, local_bug, sep="\n")
    assert log4shell["risk"] > local_bug["risk"], "Log4Shell should score higher than a minor local bug"
    assert log4shell["reasons"], "Log4Shell should come with reasons"
    assert predict([]) == []
    print("api.py ok")
