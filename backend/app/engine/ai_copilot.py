import os
from typing import Dict, Any, Optional

# MITRE ATT&CK Mapping Database
MITRE_MAPPING = {
    "Port Scanning Attempt": {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactics": ["Discovery"],
        "description": "Adversaries may attempt to get a listing of services running on remote hosts to identify exploitable entry points."
    },
    "Suspicious Port Probing": {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactics": ["Discovery"],
        "description": "Sequential port probes targeting potential remote management services."
    },
    "Possible Denial-of-Service (DoS) Attack": {
        "id": "T1498",
        "name": "Network Denial of Service",
        "tactics": ["Impact"],
        "description": "Adversary floods the network service with volumetric high-rate packets to degrade availability for legitimate users."
    },
    "Unusual Connection Frequency": {
        "id": "T1498.001",
        "name": "Direct Network Flood",
        "tactics": ["Impact"],
        "description": "Rapid packet bursts exceeding safe baseline bandwidth consumption."
    },
    "TCP NULL Scan (Stealth Probe)": {
        "id": "T1027",
        "name": "Obfuscated Network Signatures",
        "tactics": ["Defense Evasion", "Discovery"],
        "description": "Sending packets with no TCP flags set to bypass simplistic stateless firewall filters while mapping listening ports."
    },
    "TCP XMAS Scan Attack": {
        "id": "T1027",
        "name": "Protocol Manipulation",
        "tactics": ["Defense Evasion"],
        "description": "Packets with FIN, PSH, and URG flags simultaneously activated, designed to elicit different OS responses for fingerprinting."
    },
    "Statistical Anomaly (Isolation Forest)": {
        "id": "T1571",
        "name": "Non-Standard Network Communication",
        "tactics": ["Command and Control", "Initial Access"],
        "description": "Packet characteristics deviate significantly from standard enterprise statistical baseline in length, entropy, and flow timing."
    }
}

class AICopilot:
    """
    AI-Powered Threat Explainer & Incident Response Copilot.
    Generates plain-language forensic diagnoses, impact assessments,
    and automated firewall remediation scripts.
    """

    def analyze_threat(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        attack_type = alert_data.get("attack_type", "Unknown Threat")
        src_ip = alert_data.get("src_ip", "0.0.0.0")
        dst_ip = alert_data.get("dst_ip", "127.0.0.1")
        dst_port = alert_data.get("dst_port", 80)
        risk_score = alert_data.get("risk_score", 50.0)
        severity = alert_data.get("severity", "MEDIUM")
        details = alert_data.get("details", "")

        # Lookup MITRE mapping
        mitre = MITRE_MAPPING.get(attack_type, {
            "id": "T1200",
            "name": "Unclassified Anomaly",
            "tactics": ["Initial Access"],
            "description": "Behavioral aberration identified via unsupervised machine learning."
        })

        # Generate Plain-English Incident Briefing
        summary = self._generate_summary(attack_type, src_ip, dst_ip, dst_port, severity)
        mechanics = self._generate_mechanics(attack_type, details, risk_score)
        impact = self._generate_impact(attack_type, severity)
        remediation = self._generate_remediation(src_ip, dst_port)

        return {
            "threat_summary": summary,
            "mechanics_explanation": mechanics,
            "impact_assessment": impact,
            "mitre_attack": mitre,
            "recommended_actions": remediation["actions"],
            "firewall_rules": {
                "linux_iptables": remediation["iptables"],
                "linux_ufw": remediation["ufw"],
                "windows_powershell": remediation["powershell"]
            },
            "confidence_score": round(min(98.5, 75.0 + (risk_score * 0.22)), 1)
        }

    def _generate_summary(self, attack: str, src_ip: str, dst_ip: str, port: int, sev: str) -> str:
        if "Port Scan" in attack:
            return f"Host {src_ip} is conducting an active reconnaissance scan against your internal asset ({dst_ip}), systematically probing for accessible network services."
        elif "DoS" in attack:
            return f"Critical volumetric flood detected originating from {src_ip}. The host is transmitting abnormal packet surges towards {dst_ip}:{port} to exhaust system socket buffers."
        elif "NULL" in attack or "XMAS" in attack:
            return f"Stealth reconnaissance probe detected from {src_ip}. The remote host is sending crafted TCP packets with illegal flag combinations to evade standard inspection."
        elif "Isolation Forest" in attack:
            return f"Statistical anomaly flagged by Machine Learning. The connection from {src_ip} deviates from baseline corporate traffic in byte density, entropy, and flow characteristics."
        else:
            return f"Suspicious network activity originated from {src_ip} hitting {dst_ip}:{port} with elevated risk metrics."

    def _generate_mechanics(self, attack: str, details: str, risk: float) -> str:
        base = f"Event recorded with a Composite Risk Score of {risk}/100. "
        if "Port Scan" in attack:
            return base + "The engine observed a high rate of connection attempts hitting multiple distinct ports within an 8-second window, characteristic of Nmap/Masscan reconnaissance sweeps."
        elif "DoS" in attack:
            return base + "Packet arrival frequency exceeded the 40 packets/second threshold without standard TCP handshake completion (SYN-Flood dynamics)."
        elif "Isolation Forest" in attack:
            return base + "The 12-dimensional feature vector projected into an isolated decision leaf, confirming non-standard protocol behavior."
        return base + f"Forensic telemetry: {details}"

    def _generate_impact(self, attack: str, sev: str) -> str:
        if sev == "CRITICAL" or "DoS" in attack:
            return "High Risk: Potential service degradation, CPU starvation, connection timeouts for legitimate clients, and socket pool exhaustion."
        elif "Port Scan" in attack:
            return "Moderate-High Risk: Attackers use port scanning as Step 1 of an intrusion kill-chain. If an open vulnerability is discovered, exploitation attempts will follow."
        else:
            return "Moderate Risk: Information leakage or unauthorized network mapping. Asset exposure should be restricted."

    def _generate_remediation(self, src_ip: str, port: int) -> Dict[str, Any]:
        iptables_cmd = f"sudo iptables -A INPUT -s {src_ip} -j DROP"
        ufw_cmd = f"sudo ufw deny from {src_ip}"
        powershell_cmd = f'New-NetFirewallRule -DisplayName "AI-NIDS Block {src_ip}" -Direction Inbound -Action Block -RemoteAddress {src_ip}'

        actions = [
            f"Immediately blacklist source IP {src_ip} at the boundary perimeter.",
            f"Audit open services on port {port} and enforce strict IP whitelisting.",
            "Verify endpoint authentication logs for any brute-force attempts following this scan.",
            "Enable SYN-cookies on the host kernel to absorb volumetric handshake floods."
        ]

        return {
            "actions": actions,
            "iptables": iptables_cmd,
            "ufw": ufw_cmd,
            "powershell": powershell_cmd
        }

copilot = AICopilot()

