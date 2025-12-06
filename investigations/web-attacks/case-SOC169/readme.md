ecurity Incident Report: Malicious IDOR Attack**

---

### **1. Report Metadata**
| Field | Details |
| :--- | :--- |
| **Incident ID** | INC-2024-005 |
| **Date of Report** | 2024-05-21 |
| **Analyst** | Habeeb |
| **Status** | Investigated - Confirmed Malicious |
| **Severity** | **Medium** |

---

### **2. Executive Summary**
A medium-severity Insecure Direct Object Reference (IDOR) attack originating from the IP address `134.209.118.137` was detected and investigated. The threat actor attempted to bypass authorization controls to access sensitive user data by manipulating object references within the web application. Although the IP's reputation is neutral on some threat intelligence platforms, the observed activity is unequivocally malicious. Immediate containment by blocking the source IP is recommended, and remediation of the underlying application vulnerability is required.

---

### **3. Incident Details (The 5 Ws)**

*   **What:** An Insecure Direct Object Reference (IDOR) web application attack was identified. The attacker systematically altered URL parameters in an attempt to access resources and data belonging to other users.
*   **Why:** The motive was to gain unauthorized access to confidential user information, constituting a breach of data privacy.
*   **Where:** The attack targeted the company's primary web application server.
*   **When:** `[Date and Time of Attack]`
*   **Who:** The attack originated from the IP address `134.209.118.137`, which is associated with the DigitalOcean hosting provider.

---

### **4. Investigation and Analysis**

**Analyst:** Habeeb

**Summary of Actions:**
The investigation was initiated following an alert for anomalous web traffic. Analysis of web server logs revealed a series of sequential GET requests from a single IP address, where a user ID parameter was being incrementally changed. This pattern is a classic indicator of an IDOR attack. The source IP was then analyzed using multiple threat intelligence tools.

**Tool Analysis:**
*   **VirusTotal:**
    *   **Reputation:** Neutral (0 malicious votes).
    *   **Detections:** 0/95 security vendors flagged the IP.
    *   **ASN:** DIGITALOCEAN-ASN. The IP belongs to a major cloud provider, which allows for attacker anonymity.
    *   **Associated Domain:** `wiki.artstudiocompany.com`.

*   **AbuseIPDB:**
    *   The IP has been reported multiple times for malicious activities, including web application attacks and port scanning, with a low  confidence score.

*   **Talos Intelligence:**
	* Talos Intelligence have no detail about the IP address, but it still doesn't make the ip address any less malicious.
	
**Conclusion:**
While VirusTotal did not flag the IP, the direct evidence from web logs confirms a malicious IDOR attempt, web log shows multiple request to the same url for different user id which result in a response.  The reports on AbuseIPDB corroborate that this IP has been used for malicious purposes previously. The attack was a deliberate attempt to compromise data confidentiality.

---

### **5. Indicators of Compromise (IOCs)**

| Type | Value |
| :--- | :--- |
| **IP Address** | `134.209.118.137` |

---

### **6. Impact Assessment**

The attack represents a significant threat to customer data privacy. Although the full extent of data exposure is pending further review, the attacker made multiple unauthorized requests. This vulnerability could lead to a large-scale data breach if not remediated. The severity is assessed as **Medium** because the malicious attempt was confirmed, but the impact is currently contained.

---

### **7. Recommendations**

**Immediate Actions (Containment & Eradication):**
1.  **Block IP Address:** Immediately add `134.209.118.137` to the deny list on the network firewall and WAF.
2.  **Log Review:** Escalate to the application team to conduct a thorough review of logs to determine the full scope of the attacker's actions and identify if any sensitive data was successfully exfiltrated.

**Strategic Actions (Hardening & Remediation):**
1.  **Patch Vulnerability:** Escalate a high-priority ticket to the development team to fix the IDOR vulnerability. Proper server-side authorization checks must be implemented to validate that a user has permission to access the requested object.
2.  **Enhance Monitoring:** Improve WAF and SIEM rules to detect and alert on object enumeration patterns more effectively.
3.  **Vulnerability Scan:** Recommend a comprehensive vulnerability scan of the affected application to identify and address any other potential security weaknesses.
