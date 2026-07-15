# Hybrid AI-Based Penetration Testing Framework

> UCAS Cybersecurity Engineering - Graduation Project 2026
> University College of Applied Sciences - Gaza, Palestine

## Overview

A fully automated AI-powered penetration testing framework that simulates real-world red team operations across 12 sequential phases, integrating Metasploit, MITRE ATT&CK, OWASP Top 10, and Machine Learning.

## Architecture

Recon -> Scan -> Vuln Mapping -> Threat Intel -> Risk Scoring -> Exploitation -> Post-Exploitation -> MITRE ATT&CK -> AI Enrichment -> Attack Graph -> Social Engineering -> Reporting

## Key Features

- 12-Phase Automated Pipeline
- OWASP Top 10 2025 web security testing
- 3-Layer MITRE ATT&CK Engine (Rule + STIX + ML)
- Dynamic Exploitation via Metasploit + Hydra
- RandomForest ML Classifier for tactic prediction
- Attack Graph visualization
- Social Engineering campaign simulation
- SQLite Database logging

## Tech Stack

- Python 3.x, Metasploit, Nmap, Hydra, Nikto
- MITRE ATT&CK STIX, ExploitDB, CISA KEV
- scikit-learn, SQLite, NetworkX

## Usage

    git clone https://github.com/Emanmohammedsh/gradution_project.git
    cd gradution_project
    pip install -r requirements.txt
    python3 main.py

## Disclaimer

For educational purposes only. Use exclusively on systems you own or have explicit written permission to test.

Developed by Eman Mohammed - UCAS Cybersecurity Engineering 2026
