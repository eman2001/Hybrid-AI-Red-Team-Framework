"""
Social Engineering Module
=========================
Simulates rule-based social engineering attack techniques for red teaming.
Covers phishing email generation, pretexting scenarios, and OSINT-driven
target profiling. All output is for authorized penetration testing only.
"""

import random
from datetime import datetime


class SocialEngineeringModule:

    def __init__(self, target_domain: str, lhost: str):
        self.target_domain = target_domain
        self.lhost = lhost
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Pretext templates mapped to attack vector
        self.pretext_templates = {
            "it_support": {
                "sender": f"it-support@{target_domain}",
                "subject": "ACTION REQUIRED: Password Expiry Notification",
                "body": (
                    "Dear User,\n\n"
                    "Your network password is scheduled to expire in 24 hours. "
                    "To avoid losing access to company resources, please verify your "
                    "credentials immediately by visiting the link below:\n\n"
                    "  http://{lhost}/verify\n\n"
                    "Failure to act will result in your account being locked.\n\n"
                    "IT Support Team\n"
                    f"{target_domain}"
                ),
                "mitre": {"id": "T1566.002", "name": "Phishing: Spearphishing Link"},
                "risk": "HIGH"
            },
            "hr_notification": {
                "sender": f"hr@{target_domain}",
                "subject": "Important: Review Your Benefits Package for 2026",
                "body": (
                    "Dear Employee,\n\n"
                    "Our HR portal has been updated with your new benefits package. "
                    "Please log in using your corporate credentials to review and accept:\n\n"
                    "  http://{lhost}/hr-portal\n\n"
                    "Deadline: 48 hours from receipt of this email.\n\n"
                    "Human Resources\n"
                    f"{target_domain}"
                ),
                "mitre": {"id": "T1566.001", "name": "Phishing: Spearphishing Attachment"},
                "risk": "HIGH"
            },
            "ceo_fraud": {
                "sender": f"ceo@{target_domain}-corp.com",  # Lookalike domain
                "subject": "Urgent Wire Transfer Request",
                "body": (
                    "Hi,\n\n"
                    "I'm currently in a meeting and need you to process an urgent wire transfer "
                    "of $15,000 to a new vendor. Please keep this confidential until finalized.\n\n"
                    "Reply to this email for account details.\n\n"
                    "Thanks,\nCEO"
                ),
                "mitre": {"id": "T1534", "name": "Internal Spearphishing / BEC"},
                "risk": "CRITICAL"
            },
            "vendor_invoice": {
                "sender": f"billing@vendor-{target_domain}.net",  # Lookalike
                "subject": "Invoice #INV-20260518 — Payment Overdue",
                "body": (
                    "Dear Accounts Payable,\n\n"
                    "Please find attached the overdue invoice for services rendered. "
                    "To avoid service interruption, kindly process payment at:\n\n"
                    "  http://{lhost}/invoice\n\n"
                    "Invoice: #INV-20260518 | Amount: $3,750.00\n\n"
                    "Vendor Billing Department"
                ),
                "mitre": {"id": "T1566.001", "name": "Phishing: Spearphishing Attachment"},
                "risk": "MEDIUM"
            }
        }

        # Pretexting call scripts
        self.vishing_scripts = {
            "it_helpdesk": (
                "Script: Pretend to be IT Helpdesk.\n"
                "  'Hi, this is [Name] from IT. We've detected unusual login activity on your account. "
                "I need to verify your identity. Can you confirm your username and I'll send you a "
                "reset link? You'll just need to click it and enter your current password to verify.'"
            ),
            "bank_fraud": (
                "Script: Pretend to be bank security team.\n"
                "  'This is the fraud department at [Bank]. We've flagged a suspicious transaction. "
                "To protect your account I'll need you to verify your OTP that was just sent to you.'"
            )
        }

    def generate_phishing_email(self, pretext_key: str) -> dict:
        """Generate a phishing email for the given pretext scenario."""
        if pretext_key not in self.pretext_templates:
            print(f"  [-] Unknown pretext: {pretext_key}")
            return {}

        template = self.pretext_templates[pretext_key]
        email = {
            "pretext":  pretext_key,
            "sender":   template["sender"],
            "subject":  template["subject"],
            "body":     template["body"].replace("{lhost}", self.lhost),
            "mitre":    template["mitre"],
            "risk":     template["risk"]
        }

        print(f"\n  [SE] Generated Phishing Email — Pretext: {pretext_key}")
        print(f"       From    : {email['sender']}")
        print(f"       Subject : {email['subject']}")
        print(f"       MITRE   : {email['mitre']['id']} — {email['mitre']['name']}")
        print(f"       Risk    : {email['risk']}")

        return email

    def osint_profiling(self, target_info: dict) -> dict:
        """
        Simulate OSINT profiling of a target organization.
        In a real engagement this would pull from LinkedIn, Shodan, Hunter.io, etc.
        Here we build a simulated profile from scan data.
        """
        print(f"\n  [SE] Running OSINT Profiling on: {self.target_domain}")

        open_services = target_info.get("open_services", [])
        emails_guessed = [
            f"admin@{self.target_domain}",
            f"it@{self.target_domain}",
            f"hr@{self.target_domain}",
            f"ceo@{self.target_domain}",
            f"finance@{self.target_domain}",
        ]

        profile = {
            "domain":          self.target_domain,
            "guessed_emails":  emails_guessed,
            "open_services":   open_services,
            "attack_surface":  self._assess_surface(open_services),
            "recommended_pretexts": self._recommend_pretexts(open_services)
        }

        print(f"       Guessed Emails       : {', '.join(emails_guessed[:3])} ...")
        print(f"       Attack Surface Score : {profile['attack_surface']}/10")
        print(f"       Recommended Pretexts : {', '.join(profile['recommended_pretexts'])}")

        return profile

    def _assess_surface(self, services: list) -> int:
        """Score the social engineering attack surface out of 10."""
        score = 3  # baseline
        if "smtp" in services or "mail" in services:
            score += 2   # Can send spoofed email internally
        if "http" in services or "https" in services:
            score += 2   # Can host credential harvester
        if "rdp" in services or "vnc" in services:
            score += 2   # Vishing for remote access
        if "ssh" in services:
            score += 1
        return min(score, 10)

    def _recommend_pretexts(self, services: list) -> list:
        """Recommend attack pretexts based on discovered services."""
        recommended = []
        if "http" in services or "https" in services:
            recommended.append("it_support")
            recommended.append("hr_notification")
        if "smtp" in services:
            recommended.append("ceo_fraud")
            recommended.append("vendor_invoice")
        if not recommended:
            recommended = ["it_support"]  # Default fallback
        return recommended

    def run_campaign(self, target_info: dict) -> dict:
        """
        Run a full simulated social engineering campaign:
        1. OSINT profiling
        2. Select best pretexts
        3. Generate phishing emails
        4. Suggest vishing scripts
        """
        print(f"\n[Social Engineering] Starting Campaign against: {self.target_domain}")
        print(f"[Social Engineering] Credential Harvester: http://{self.lhost}/harvest")

        profile = self.osint_profiling(target_info)

        emails_generated = []
        for pretext_key in profile["recommended_pretexts"]:
            email = self.generate_phishing_email(pretext_key)
            if email:
                emails_generated.append(email)

        # Pick a vishing script
        vishing_key = random.choice(list(self.vishing_scripts.keys()))
        vishing = {
            "type": vishing_key,
            "script": self.vishing_scripts[vishing_key]
        }
        print(f"\n  [SE] Vishing Script — {vishing_key}")
        print(f"       {vishing['script'][:120]}...")

        campaign_result = {
            "domain":           self.target_domain,
            "osint_profile":    profile,
            "phishing_emails":  emails_generated,
            "vishing":          vishing,
            "mitre_tactics":    [
                {"id": "T1598", "name": "Phishing for Information"},
                {"id": "T1566", "name": "Phishing"},
                {"id": "T1534", "name": "Internal Spearphishing"},
            ]
        }

        print(f"\n  [+] Campaign Complete.")
        print(f"  [+] Emails Generated : {len(emails_generated)}")
        print(f"  [+] MITRE Tactics    : {', '.join(t['id'] for t in campaign_result['mitre_tactics'])}")

        return campaign_result
