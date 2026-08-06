"""
dataset_generator.py
=====================
Generates a realistic, rule-grounded synthetic dataset for a defensive
decision-support classifier used in an authorized security assessment
framework.

IMPORTANT SCOPE NOTE
---------------------
This generator does NOT produce exploits, payloads, attack chains, or
offensive instructions of any kind. It produces abstract *state summaries*
of a lab endpoint (what category of information has/has not yet been
collected, at a coarse level) and labels each state with the single most
appropriate NEXT-OBJECTIVE from a fixed taxonomy of assessment activities
(e.g. "look at running processes next" / "the session is basically done").
This is the same category of problem as a triage/next-best-action system
used in ITSM or SOC tooling.

Run:
    python dataset_generator.py --n 5000 --out data/training_data.csv
"""

import argparse
import random
from dataclasses import dataclass, asdict

import numpy as np
import pandas as pd

RANDOM_SEED = 42

OS_TYPES = ["windows", "linux", "macos"]
ARCHITECTURES = ["x64", "x86", "arm64"]
PRIVILEGE_LEVELS = ["low", "medium", "high", "system"]
SESSION_TYPES = ["interactive", "remote", "service"]
CREDENTIAL_INDICATORS = ["none", "weak_hashes", "cached_creds", "plaintext_found"]

BOOLEAN_FEATURES = [
    "domain_joined",
    "multiple_users_logged_in",
    "high_process_count",
    "suspicious_process_present",
    "multiple_network_interfaces",
    "active_external_connections",
    "security_software_present",
    "remote_management_enabled",
    "unusual_services_present",
    "scheduled_tasks_present",
    "unusual_scheduled_tasks",
    "sensitive_files_indicator",
    "system_info_collected",
    "user_info_collected",
    "process_info_collected",
    "service_info_collected",
    "network_info_collected",
    "config_info_collected",
    "security_controls_reviewed",
    "account_info_collected",
    "risk_assessment_done",
]

LABELS = [
    "System Discovery",
    "User Assessment",
    "Process Analysis",
    "Service Analysis",
    "Network Assessment",
    "Configuration Review",
    "Security Control Review",
    "Account Assessment",
    "Risk Assessment",
    "Session Completion",
]

COVERAGE_ORDER = [
    ("system_info_collected", "System Discovery"),
    ("user_info_collected", "User Assessment"),
    ("process_info_collected", "Process Analysis"),
    ("service_info_collected", "Service Analysis"),
    ("network_info_collected", "Network Assessment"),
    ("config_info_collected", "Configuration Review"),
    ("security_controls_reviewed", "Security Control Review"),
    ("account_info_collected", "Account Assessment"),
    ("risk_assessment_done", "Risk Assessment"),
]


@dataclass
class EndpointState:
    os_type: str
    architecture: str
    privilege_level: str
    session_type: str
    credential_indicator: str
    domain_joined: int
    multiple_users_logged_in: int
    high_process_count: int
    suspicious_process_present: int
    multiple_network_interfaces: int
    active_external_connections: int
    security_software_present: int
    remote_management_enabled: int
    unusual_services_present: int
    scheduled_tasks_present: int
    unusual_scheduled_tasks: int
    sensitive_files_indicator: int
    system_info_collected: int
    user_info_collected: int
    process_info_collected: int
    service_info_collected: int
    network_info_collected: int
    config_info_collected: int
    security_controls_reviewed: int
    account_info_collected: int
    risk_assessment_done: int


def sample_state(rng: random.Random) -> EndpointState:
    os_type = rng.choices(OS_TYPES, weights=[0.55, 0.35, 0.10])[0]
    architecture = rng.choices(ARCHITECTURES, weights=[0.75, 0.10, 0.15])[0]
    privilege_level = rng.choices(
        PRIVILEGE_LEVELS, weights=[0.40, 0.30, 0.22, 0.08]
    )[0]
    session_type = rng.choices(SESSION_TYPES, weights=[0.45, 0.40, 0.15])[0]

    domain_joined = rng.choices([1, 0], weights=[0.65, 0.35])[0]
    security_software_present = rng.choices(
        [1, 0], weights=[0.8, 0.2] if domain_joined else [0.45, 0.55]
    )[0]

    multiple_users_logged_in = rng.choices([1, 0], weights=[0.25, 0.75])[0]
    high_process_count = rng.choices([1, 0], weights=[0.35, 0.65])[0]
    suspicious_process_present = rng.choices([1, 0], weights=[0.15, 0.85])[0]
    multiple_network_interfaces = rng.choices([1, 0], weights=[0.30, 0.70])[0]
    active_external_connections = rng.choices([1, 0], weights=[0.30, 0.70])[0]
    remote_management_enabled = rng.choices([1, 0], weights=[0.40, 0.60])[0]
    unusual_services_present = rng.choices([1, 0], weights=[0.20, 0.80])[0]
    scheduled_tasks_present = rng.choices([1, 0], weights=[0.55, 0.45])[0]
    unusual_scheduled_tasks = (
        rng.choices([1, 0], weights=[0.30, 0.70])[0] if scheduled_tasks_present else 0
    )
    sensitive_files_indicator = rng.choices([1, 0], weights=[0.20, 0.80])[0]

    if privilege_level in ("high", "system"):
        credential_indicator = rng.choices(
            CREDENTIAL_INDICATORS, weights=[0.30, 0.25, 0.25, 0.20]
        )[0]
    else:
        credential_indicator = rng.choices(
            CREDENTIAL_INDICATORS, weights=[0.55, 0.25, 0.15, 0.05]
        )[0]

    coverage = {}
    progressed = True
    for flag_name, _ in COVERAGE_ORDER:
        if progressed:
            done = rng.choices([1, 0], weights=[0.55, 0.45])[0]
        else:
            done = rng.choices([1, 0], weights=[0.15, 0.85])[0]
        coverage[flag_name] = done
        if not done:
            progressed = False

    return EndpointState(
        os_type=os_type,
        architecture=architecture,
        privilege_level=privilege_level,
        session_type=session_type,
        credential_indicator=credential_indicator,
        domain_joined=domain_joined,
        multiple_users_logged_in=multiple_users_logged_in,
        high_process_count=high_process_count,
        suspicious_process_present=suspicious_process_present,
        multiple_network_interfaces=multiple_network_interfaces,
        active_external_connections=active_external_connections,
        security_software_present=security_software_present,
        remote_management_enabled=remote_management_enabled,
        unusual_services_present=unusual_services_present,
        scheduled_tasks_present=scheduled_tasks_present,
        unusual_scheduled_tasks=unusual_scheduled_tasks,
        sensitive_files_indicator=sensitive_files_indicator,
        **coverage,
    )


def determine_next_objective(state: EndpointState) -> tuple[str, str]:
    if state.credential_indicator == "plaintext_found" and not state.risk_assessment_done:
        return (
            "Risk Assessment",
            "Plaintext credential material was indicated, which represents a "
            "significant exposure that should be escalated to risk assessment "
            "ahead of the normal checklist order.",
        )

    if (
        state.suspicious_process_present
        and state.unusual_scheduled_tasks
        and not state.risk_assessment_done
    ):
        return (
            "Risk Assessment",
            "A suspicious process combined with an unusual scheduled task "
            "suggests a persistence mechanism; this warrants prioritized "
            "risk assessment.",
        )

    if (
        state.security_software_present
        and state.unusual_services_present
        and not state.security_controls_reviewed
    ):
        return (
            "Security Control Review",
            "Unusual services were observed on a host with security software "
            "present, so verifying which controls are actually enforced is "
            "the most informative next step.",
        )

    for flag_name, label in COVERAGE_ORDER:
        if not getattr(state, flag_name):
            reason_map = {
                "System Discovery": "Baseline system information (OS, architecture, "
                "privilege context) has not yet been collected for this session.",
                "User Assessment": "Logged-in user and session context has not yet "
                "been reviewed.",
                "Process Analysis": "Running process information has not yet been "
                "analyzed for this endpoint.",
                "Service Analysis": "Installed/running services have not yet been "
                "reviewed for misconfiguration or excess exposure.",
                "Network Assessment": "Network interfaces and active connections "
                "have not yet been characterized.",
                "Configuration Review": "Host and file-system configuration has not "
                "yet been reviewed.",
                "Security Control Review": "Installed security controls (AV/EDR, "
                "remote management posture) have not yet been reviewed.",
                "Account Assessment": "Account and credential posture has not yet "
                "been assessed.",
                "Risk Assessment": "All discovery areas are covered; consolidating "
                "findings into an overall risk assessment is the logical next step.",
            }
            return label, reason_map[label]

    return (
        "Session Completion",
        "All checklist areas (discovery, users, processes, services, network, "
        "configuration, security controls, accounts, risk) have been covered "
        "for this session, so no further collection objective remains.",
    )


def generate_dataset(n_samples: int, noise_rate: float, seed: int) -> pd.DataFrame:
    rng = random.Random(seed)
    np_rng = np.random.default_rng(seed)

    per_label_target = n_samples // len(LABELS)
    rows = []
    label_counts = {label: 0 for label in LABELS}

    attempts = 0
    max_attempts = n_samples * 60
    while sum(label_counts.values()) < per_label_target * len(LABELS) and attempts < max_attempts:
        attempts += 1
        state = sample_state(rng)
        label, reason = determine_next_objective(state)
        if label_counts[label] >= per_label_target:
            continue
        label_counts[label] += 1
        row = asdict(state)
        row["label"] = label
        row["explanation"] = reason
        rows.append(row)

    df = pd.DataFrame(rows)

    n_noisy = int(len(df) * noise_rate)
    noisy_idx = np_rng.choice(df.index, size=n_noisy, replace=False)
    for idx in noisy_idx:
        current = df.at[idx, "label"]
        alternatives = [l for l in LABELS if l != current]
        new_label = rng.choice(alternatives)
        df.at[idx, "label"] = new_label
        df.at[idx, "explanation"] = (
            df.at[idx, "explanation"]
            + " (Note: relabeled to reflect natural assessor judgement variance.)"
        )

    df = df.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    return df


def main():
    parser = argparse.ArgumentParser(description="Generate synthetic assessment-objective dataset")
    parser.add_argument("--n", type=int, default=5000, help="Total number of samples")
    parser.add_argument("--noise", type=float, default=0.03, help="Label noise rate (0-1)")
    parser.add_argument("--seed", type=int, default=RANDOM_SEED)
    parser.add_argument("--out", type=str, default="data/training_data.csv")
    args = parser.parse_args()

    df = generate_dataset(args.n, args.noise, args.seed)
    df.to_csv(args.out, index=False)

    print(f"Generated {len(df)} rows -> {args.out}")
    print("\nClass balance:")
    print(df["label"].value_counts())


if __name__ == "__main__":
    main()
