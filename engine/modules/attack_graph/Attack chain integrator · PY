"""
post_exploitation/attack_chain_integrator.py
----------------------------------------------
Merges post-exploitation evidence into the attack chain built by ChainBuilder.

FIX: was never called from main.py — now integrated.

The integrate() method appends new phases to an existing chain dict and also
enriches any matching existing phase with post-exploit confidence data.
"""

from __future__ import annotations


class AttackChainIntegrator:

    # MITRE technique references for each post-exploit category
    _PHASE_MAP = {
        "credential_access": {
            "phase_name": "Credential Access",
            "tactic":     "credential-access",
            "techniques": [{"id": "T1003", "name": "OS Credential Dumping"}],
            "confidence": 0.95,
        },
        "discovery": {
            "phase_name": "Discovery",
            "tactic":     "discovery",
            "techniques": [
                {"id": "T1082", "name": "System Information Discovery"},
                {"id": "T1016", "name": "System Network Configuration Discovery"},
                {"id": "T1057", "name": "Process Discovery"},
                {"id": "T1033", "name": "System Owner/User Discovery"},
            ],
            "confidence": 0.95,
        },
        "privilege_escalation": {
            "phase_name": "Privilege Escalation",
            "tactic":     "privilege-escalation",
            "techniques": [{"id": "T1068", "name": "Exploitation for Privilege Escalation"}],
            "confidence": 0.90,
        },
        "persistence": {
            "phase_name": "Persistence",
            "tactic":     "persistence",
            "techniques": [{"id": "T1547", "name": "Boot/Logon Autostart Execution"}],
            "confidence": 0.85,
        },
        "lateral_movement": {
            "phase_name": "Lateral Movement",
            "tactic":     "lateral-movement",
            "techniques": [
                {"id": "T1021", "name": "Remote Services"},
                {"id": "T1075", "name": "Pass the Hash"},
            ],
            "confidence": 0.80,
        },
    }

    def integrate(self, post_data: dict, attack_chain: dict) -> dict:
        """
        Append post-exploitation phases to the attack chain.

        Parameters
        ----------
        post_data    : output of PostExploitModule.run_post_exploitation()
        attack_chain : output of MitreEngine.build_chain()

        Returns
        -------
        Enriched attack_chain (mutated + returned)
        """
        host = post_data.get("host", "unknown")
        added = 0

        # ── Credential Access ─────────────────────────────────────────
        if post_data.get("hashes"):
            self._append_phase(
                attack_chain, "credential_access", host,
                extra={"credential_count": len(post_data["hashes"])}
            )
            added += 1

        # ── Discovery (always present if sysinfo ran) ─────────────────
        if post_data.get("sysinfo") or post_data.get("arp_hosts"):
            self._append_phase(
                attack_chain, "discovery", host,
                extra={
                    "arp_hosts_found": len(post_data.get("arp_hosts", [])),
                    "os":              post_data.get("sysinfo", {}).get("os", "N/A"),
                }
            )
            added += 1

        # ── Privilege Escalation ──────────────────────────────────────
        if post_data.get("privesc_vectors"):
            self._append_phase(
                attack_chain, "privilege_escalation", host,
                extra={"vectors": [v["name"] for v in post_data["privesc_vectors"]]}
            )
            added += 1

        # ── Persistence ───────────────────────────────────────────────
        if post_data.get("persist_mechs"):
            self._append_phase(
                attack_chain, "persistence", host,
                extra={"mechanisms": [m["name"] for m in post_data["persist_mechs"]]}
            )
            added += 1

        # ── Lateral Movement ─────────────────────────────────────────
        lateral = post_data.get("lateral_opps") or post_data.get("lateral_opportunities", [])
        if lateral:
            self._append_phase(
                attack_chain, "lateral_movement", host,
                extra={"targets": [o.get("target") for o in lateral]}
            )
            added += 1

        # ── Merge MITRE techniques from MitrePostMapper ───────────────
        self._merge_mitre_techniques(attack_chain, post_data.get("mitre_techniques", []), host)

        print(f"  [ChainIntegrator] +{added} post-exploit phases merged into attack chain "
              f"(total={len(attack_chain)} phases)")
        return attack_chain

    # ── Private helpers ────────────────────────────────────────────────

    def _append_phase(self, chain: dict, category: str,
                      host: str, extra: dict | None = None) -> None:
        template  = self._PHASE_MAP[category]
        phase_num = str(len(chain) + 1)

        # If a phase with same tactic already exists — enrich it instead
        for phase in chain.values():
            if phase.get("tactic") == template["tactic"]:
                if host not in phase.get("hosts", []):
                    phase.setdefault("hosts", []).append(host)
                phase["source"] = "post_exploit+mitre"
                if extra:
                    phase.setdefault("post_evidence", {}).update(extra)
                return

        chain[phase_num] = {
            "phase_name":    template["phase_name"],
            "tactic":        template["tactic"],
            "techniques":    template["techniques"],
            "hosts":         [host],
            "confidence":    template["confidence"],
            "source":        "post_exploit",
            "post_evidence": extra or {},
        }

    def _merge_mitre_techniques(self, chain: dict,
                                mitre_techs: list[dict], host: str) -> None:
        """
        For each technique from MitrePostMapper, find the matching tactic
        phase in chain and inject the technique if not already present.
        """
        for tech in mitre_techs:
            tactic = tech.get("tactic", "")
            tid    = tech.get("technique_id", "")
            if not tactic or not tid:
                continue
            for phase in chain.values():
                if phase.get("tactic") == tactic:
                    existing_ids = [t["id"] for t in phase.get("techniques", [])]
                    if tid not in existing_ids:
                        phase["techniques"].append({
                            "id":   tid,
                            "name": tech.get("technique_name", ""),
                        })
                    break
