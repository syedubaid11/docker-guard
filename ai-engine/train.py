"""Train the DockerGuard exploit-prediction model.

Question the model answers: "is this CVE likely to be used in real attacks?"
Label: 1 if the CVE is in CISA's Known Exploited Vulnerabilities (KEV) list, else 0.

Run (Google Colab, or any Python 3.10+):
    pip install -r requirements.txt
    python train.py

Outputs in ./out:
    metrics.csv        comparison table of the three models and two baselines
    shap_summary.png   which features push the risk score up or down
    model.joblib       the trained XGBoost model + its feature builder, for the API
"""
import gzip
import json
import shutil
import urllib.request
from pathlib import Path

import joblib
import matplotlib

matplotlib.use("Agg")  # no screen needed; we only save the plot to a file
import matplotlib.pyplot as plt
import pandas as pd
import shap
import xgboost
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, average_precision_score, f1_score, precision_score, recall_score
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import MaxAbsScaler, OneHotEncoder

from features import CVSS_KEYS, to_frame

HERE = Path(__file__).parent
DATA, OUT = HERE / "data", HERE / "out"
NOW = pd.Timestamp.now(tz="UTC")

# Start at 2016: older CVEs only have a CVSS v3 vector if NVD went back and re-scored them,
# which happened mostly for exploited ones, so including them would leak the label.
YEARS = range(2016, NOW.year + 1)
NVD = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{}.json.gz"
KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"


def fetch(url, name):
    path = DATA / name
    if not path.exists():
        print("downloading", name)
        request = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        part = DATA / (name + ".part")  # so a download that dies halfway is not mistaken for a full file
        with urllib.request.urlopen(request) as response, open(part, "wb") as f:
            shutil.copyfileobj(response, f)
        part.rename(path)
    return path


def load_year(year):
    # shortcut: loads a whole year of JSON into memory (about 2 GB at peak for recent years);
    # switch to a streaming parser (ijson) if this runs out of RAM.
    with gzip.open(fetch(NVD.format(year), f"nvd-{year}.json.gz"), "rt", encoding="utf-8") as f:
        items = json.load(f)["vulnerabilities"]

    rows = []
    for item in items:
        cve = item["cve"]
        metrics = cve.get("metrics", {})
        cvss = metrics.get("cvssMetricV31", []) + metrics.get("cvssMetricV30", [])
        if not cvss:
            continue  # no CVSS v3 vector, so nothing to build features from
        cvss = next((m for m in cvss if m.get("type") == "Primary"), cvss[0])["cvssData"]
        # Deliberately NOT read: cisaExploitAdd, the ssvc "exploitation" field and the references.
        # They are filled in after an attack is known, so using them would be cheating.
        rows.append({
            "id": cve["id"],
            "vector": cvss["vectorString"],
            "score": cvss["baseScore"],
            "cwes": [d["value"] for w in cve.get("weaknesses", []) for d in w["description"]],
            "published": cve["published"],
            "description": next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), ""),
        })
    return rows


def score_row(name, y_true, score, predicted):
    return {
        "model": name,
        "accuracy": accuracy_score(y_true, predicted),
        "precision": precision_score(y_true, predicted, zero_division=0),
        "recall": recall_score(y_true, predicted),
        "f1": f1_score(y_true, predicted),
        # PR-AUC judges the ranking itself (no cut-off needed); the key number when under 1% of rows are positive.
        "pr_auc": average_precision_score(y_true, score),
    }


def main():
    DATA.mkdir(exist_ok=True)
    OUT.mkdir(exist_ok=True)

    kev = json.loads(fetch(KEV, "kev.json").read_text(encoding="utf-8"))
    exploited = {v["cveID"] for v in kev["vulnerabilities"]}

    df = to_frame([row for year in YEARS for row in load_year(year)], NOW)
    df["label"] = df["id"].isin(exploited).astype(int)

    # Split by time, not at random: train on older CVEs, test on the newest 20%.
    # This is how the model is really used (predicting for CVEs it has never seen).
    df = df.sort_values("published")
    cut = int(len(df) * 0.8)
    train, test = df.iloc[:cut], df.iloc[cut:]
    y_train, y_test = train["label"], test["label"]
    assert y_train.sum() and y_test.sum(), "no exploited CVEs in one of the splits"
    print(f"train: {len(train)} CVEs, {y_train.sum()} exploited | test: {len(test)} CVEs, {y_test.sum()} exploited")

    pre = ColumnTransformer(
        [
            ("cvss", OneHotEncoder(handle_unknown="ignore"), CVSS_KEYS),
            ("cwe", OneHotEncoder(handle_unknown="infrequent_if_exist", min_frequency=50), ["cwe"]),
            ("num", "passthrough", ["cvss_score", "age_days"]),
            ("text", TfidfVectorizer(max_features=3000, ngram_range=(1, 2), stop_words="english", min_df=5), "description"),
        ],
        sparse_threshold=1.0,
    )
    X_train, X_test = pre.fit_transform(train), pre.transform(test)

    # Exploited CVEs are rare, so each one is given more weight; otherwise a model can score
    # 99% accuracy by always answering "safe".
    imbalance = (y_train == 0).sum() / y_train.sum()
    models = {
        "Logistic Regression": make_pipeline(
            MaxAbsScaler(), LogisticRegression(class_weight="balanced", max_iter=1000)
        ),
        "Random Forest": RandomForestClassifier(
            n_estimators=200, min_samples_leaf=5, class_weight="balanced_subsample", n_jobs=-1, random_state=0
        ),
        "XGBoost": xgboost.XGBClassifier(
            n_estimators=400,
            max_depth=6,
            learning_rate=0.05,
            subsample=0.8,
            colsample_bytree=0.8,
            scale_pos_weight=imbalance,
            tree_method="hist",
            eval_metric="aucpr",
            random_state=0,
        ),
    }

    epss = pd.read_csv(fetch(EPSS, "epss.csv.gz"), comment="#").set_index("cve")["epss"]
    test_epss = test["id"].map(epss).fillna(0)
    results = [
        score_row("CVSS >= 9 (baseline)", y_test, test["cvss_score"], test["cvss_score"] >= 9),
        score_row("EPSS >= 0.1 (baseline)", y_test, test_epss, test_epss >= 0.1),
    ]
    for name, model in models.items():
        print("training", name)
        model.fit(X_train, y_train)
        score = model.predict_proba(X_test)[:, 1]
        results.append(score_row(name, y_test, score, score >= 0.5))

    table = pd.DataFrame(results).round(4)
    table.to_csv(OUT / "metrics.csv", index=False)
    print(table.to_string(index=False))

    # Explainable AI: SHAP values on ~3000 test CVEs spread across the whole test period.
    # XGBoost computes SHAP values itself (pred_contribs); the last column is the base value.
    xgb = models["XGBoost"]
    sample = X_test[:: max(1, X_test.shape[0] // 3000)]
    contributions = xgb.get_booster().predict(xgboost.DMatrix(sample), pred_contribs=True)[:, :-1]
    shap.summary_plot(
        contributions, sample.toarray(), feature_names=list(pre.get_feature_names_out()), max_display=20, show=False
    )
    plt.savefig(OUT / "shap_summary.png", dpi=150, bbox_inches="tight")

    # XGBoost is the model the API serves (it is the one SHAP explains above).
    # If another model wins in metrics.csv, say so in the report rather than hiding it.
    joblib.dump({"pre": pre, "model": xgb}, OUT / "model.joblib")
    print("saved", OUT / "model.joblib")


if __name__ == "__main__":
    main()
