"""
train_mitre_model.py
--------------------
Trains the MITRE ATT&CK tactic classifier (TF-IDF + Random Forest).

v2: Builds training data automatically from the official STIX enterprise-attack.json
    (709 techniques -> 890+ samples) and merges with the original hand-crafted set.

Run once before starting the pipeline:
    python train_mitre_model.py

Outputs:
    models/mitre_classifier.pkl
    data/stix_training.csv
"""

import csv
import json
import os
import pickle
import re

from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

STIX_PATH         = "data/enterprise-attack.json"
STIX_TRAINING_CSV = "data/stix_training.csv"
MODEL_PATH        = "models/mitre_classifier.pkl"

TACTIC_ALIASES = {
    "stealth":            "defense-evasion",
    "defense-impairment": "defense-evasion",
}

HANDCRAFTED_DATA = [
    ("vsftpd backdoor remote code execution ftp 21",           "initial-access"),
    ("samba usermap script smb 445 command injection",         "lateral-movement"),
    ("eternalblue ms17 smb 445 windows",                       "lateral-movement"),
    ("bluekeep rdp 3389 windows remote",                       "lateral-movement"),
    ("drupalgeddon web http 80 exploit",                       "initial-access"),
    ("struts ognl injection http 8080 java",                   "initial-access"),
    ("unreal ircd backdoor irc 6667",                          "initial-access"),
    ("distcc exec remote code linux 3632",                     "initial-access"),
    ("java rmi server lateral 1099",                           "lateral-movement"),
    ("ms08 netapi smb 445 windows buffer overflow",            "lateral-movement"),
    ("ssh brute force credential 22",                          "credential-access"),
    ("ftp brute force credential 21",                          "credential-access"),
    ("telnet brute force valid accounts 23",                   "credential-access"),
    ("rdp brute force credential 3389",                        "credential-access"),
    ("mysql brute force credential 3306",                      "credential-access"),
    ("hashdump credential dump ntlm windows",                  "credential-access"),
    ("ssh private key credential dump linux",                  "credential-access"),
    ("getsystem privilege escalation windows",                 "privilege-escalation"),
    ("sudo nopasswd privilege escalation linux",               "privilege-escalation"),
    ("local exploit suggester privilege linux windows",        "privilege-escalation"),
    ("sysinfo discovery system information",                   "discovery"),
    ("getuid user discovery system owner",                     "discovery"),
    ("arp route network discovery enum",                       "discovery"),
    ("ping sweep remote system discovery network",             "discovery"),
    ("process list discovery ps windows linux",                "discovery"),
    ("meterpreter command shell execution interpreter",        "execution"),
    ("bash shell command scripting interpreter linux",         "execution"),
    ("powershell command scripting windows execution",         "execution"),
    ("web application exploit public facing http",             "initial-access"),
    ("php cgi argument injection web 80",                      "initial-access"),
    ("wordpress admin shell upload http",                      "initial-access"),
    ("jenkins script console http 8080",                       "execution"),
    ("exfiltration ftp c2 channel data",                       "exfiltration"),
    ("phishing spearphishing email smtp link",                 "initial-access"),
    ("scheduled task persistence cron windows",                "persistence"),
    ("registry run key persistence windows",                   "persistence"),
    ("lateral movement psexec smb windows",                    "lateral-movement"),
    ("remote services ssh linux lateral",                      "lateral-movement"),
    ("collection files directory discovery",                   "collection"),
    ("impact ransomware encryption data",                      "impact"),
]


def _clean(text):
    text = re.sub(r"```.*?```", " ", text, flags=re.DOTALL)
    text = re.sub(r"`[^`]+`", " ", text)
    text = re.sub(r"https?://\S+", " ", text)
    text = re.sub(r"[/_\-\.\(\)\[\]]", " ", text)
    text = re.sub(r"\s+", " ", text).strip().lower()
    return text


def _tech_to_text(obj):
    name  = obj.get("name", "")
    desc  = obj.get("description", "")[:400]
    plats = " ".join(obj.get("x_mitre_platforms", []))
    return _clean(f"{name} {desc} {plats}")


def build_stix_samples(stix_path):
    if not os.path.exists(stix_path):
        print(f"  [!] STIX file not found: {stix_path}")
        return []

    print(f"  [*] Loading STIX data from {stix_path} ...")
    with open(stix_path, encoding="utf-8") as f:
        data = json.load(f)

    samples = []
    skipped = 0

    for obj in data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            skipped += 1
            continue

        text = _tech_to_text(obj)
        if not text:
            continue

        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") != "mitre-attack":
                continue
            tactic = phase.get("phase_name", "").strip()
            tactic = TACTIC_ALIASES.get(tactic, tactic)
            if tactic:
                samples.append((text, tactic))

    print(f"  [+] Extracted {len(samples)} samples ({skipped} skipped).")
    return samples


def save_stix_csv(samples, path):
    os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["text", "tactic"])
        writer.writerows(samples)
    print(f"  [+] Saved {len(samples)} samples -> {path}")


def normalize(text):
    return re.sub(r"[/_\-]", " ", text.lower())


def train():
    print("\n[MITRE Classifier Training - v2 STIX-augmented]\n")

    stix_samples = build_stix_samples(STIX_PATH)
    save_stix_csv(stix_samples, STIX_TRAINING_CSV)

    all_samples = stix_samples + HANDCRAFTED_DATA
    texts   = [normalize(t[0]) for t in all_samples]
    tactics = [t[1] for t in all_samples]

    print(f"\n  Total training samples : {len(texts)}")

    from collections import Counter
    dist = Counter(tactics)
    print("  Tactic distribution:")
    for tactic, count in sorted(dist.items(), key=lambda x: -x[1]):
        bar = "=" * (count // 5)
        print(f"    {tactic:<30} {count:>4}  {bar}")

    le = LabelEncoder()
    y  = le.fit_transform(tactics)

    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=2000,
        min_df=2,
        sublinear_tf=True,
    )
    X = vectorizer.fit_transform(texts)

    print(f"\n  Vocabulary size : {len(vectorizer.vocabulary_)}")
    print(f"  Feature matrix  : {X.shape[0]} x {X.shape[1]}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.15, random_state=42, stratify=y
    )
    print(f"  Train / Test    : {X_train.shape[0]} / {X_test.shape[0]}")

    print("\n  [*] Training Random Forest classifier ...")
    model = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        min_samples_leaf=2,
        random_state=42,
        class_weight="balanced",
        n_jobs=-1,
    )
    model.fit(X_train, y_train)

    y_pred   = model.predict(X_test)
    accuracy = (y_pred == y_test).mean()
    print(f"\n  Test Accuracy   : {accuracy:.1%}\n")
    print("  Classification Report:")
    print(classification_report(y_test, y_pred, target_names=le.classes_, zero_division=0))

    os.makedirs("models", exist_ok=True)
    with open(MODEL_PATH, "wb") as f:
        pickle.dump({
            "model":         model,
            "vectorizer":    vectorizer,
            "label_encoder": le,
            "version":       "2.0-stix",
            "n_train":       X_train.shape[0],
            "accuracy":      round(accuracy, 4),
        }, f)

    print(f"\n  [+] Model saved -> {MODEL_PATH}")
    print(f"  [+] Tactics covered ({len(le.classes_)}): {list(le.classes_)}")
    print(f"  [+] Training samples : {len(texts)} ({len(stix_samples)} STIX + {len(HANDCRAFTED_DATA)} hand-crafted)")


if __name__ == "__main__":
    train()
