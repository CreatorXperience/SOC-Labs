Incident Report: LFI Attack - High Severity

**Incident ID:** SOC170
**Date:** Mar, 01, 2022, 10:10 AM
**Analyst:** Habeeb

---

### 1. Executive Summary

A Local File Inclusion (LFI) attack was detected on the internal network. The attacker attempted to access sensitive system files, specifically the `/etc/passwd` file, indicating an attempt to gain unauthorized access to user account information and potentially escalate privileges.  The incident is assessed as **High Severity** due to the potential for significant compromise.

---

### 2. Incident Details

*   **What:** Local File Inclusion (LFI) Attack
*   **Why:** The attacker exploited a vulnerability allowing them to include local files, specifically targeting `/etc/passwd` to enumerate user accounts. This suggests an attempt to map the local file system and potentially gain unauthorized access.
*   **Where:** Internal Network
*   **When:** Mar, 01, 2022, 10:10 AM 
*   **Who:** An Attacker  

---

### 3. Technical Analysis

The attack involved an attempt to include local files via a vulnerable application or script. The target file, `/etc/passwd`, contains user account information. Successful exploitation could lead to:

*   User enumeration
*   Potential password cracking (if shadow file is also accessible)
*   Privilege escalation
*   Further compromise of internal systems

**Indicators of Compromise (IOCs):**

*   **IP Address:** 106.55.45.162

**IOC Context (VirusTotal):**

*   **Country:** China (CN)
*   **ASN:** AS106.52.0.0/14 - Shenzhen Tencent Computer Systems Company Limited
*   **VirusTotal Reputation:** -16 (Poor)
*   **Community Votes:** 6 Malicious / 1 Harmless
*   **Detection Rate:** 0/61 - No engines flagged as malicious, 61 flagged as harmless, 34 undetected.  *Note: A low malicious detection rate does not negate the malicious intent, especially given the context of the LFI attempt.*
*   **Associated TLS Certificate/Domains:** Certificate exists, but details are limited. Further investigation of associated domains is recommended.

---

### 4. Investigation Steps

The following tools were used during the investigation:

*   VirusTotal
*   AbuseIPDB
*   Cisco Talos

The IP address (106.55.45.162) was investigated using the above tools to determine its reputation and associated threats.  The VirusTotal report indicates a poor reputation score and a history of malicious activity reported by the community.

---

### 5. Remediation & Next Steps

*   **Immediate Action:** Block the identified IP address (106.55.45.162) at the firewall and intrusion prevention system (IPS).
*   **Vulnerability Assessment:** Conduct a thorough vulnerability assessment of all web applications and scripts to identify and patch any LFI vulnerabilities.
*   **Log Review:**  Review application and system logs for further evidence of the attack and any successful exploitation attempts.
*   **Account Monitoring:** Monitor user accounts for suspicious activity.
*   **Further Investigation:** Investigate the source of the attack and identify any potentially compromised systems or accounts.
*   **Implement WAF Rules:** Implement Web Application Firewall (WAF) rules to prevent future LFI attacks.



---

### 6. Severity Assessment

**High** - The attacker targeted a sensitive system file, indicating a clear intent to compromise the system. Successful exploitation could lead to significant data breach and system compromise.
