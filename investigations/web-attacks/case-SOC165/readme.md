# Incident Report – SQL Injection Attempt

**Date:**Feb, 25, 2022, 11:34 AM  
**Analyst:** **Habeeb Muhydeen  
**Platform:** Let’s Defend  
**Incident Type:** SQL Injection Attack  
**Severity:** Medium  
**Status:** Resolved  

--

## 1. Summary

On *[insert date/time]*, an alert was triggered on the Let’s Defend SOC platform indicating suspicious inbound traffic targeting the company network. Further investigation confirmed that the event was a **SQL Injection attack attempt** originating from a malicious IP address hosted by DigitalOcean.

The attack was **not successful**, and there was **no need for Tier 2 escalation** based on the playbook evaluation.

---

## 2. Playbook Answers

| Playbook Question                     | Analyst Answer              |
|---------------------------------------|-----------------------------|
| Do You Need Tier 2 Escalation?        | **No**                      |
| Was the Attack Successful?            | **No**                      |
| What Is the Direction of Traffic?     | **Internet → Company Network** |
| Check if It Is a Planned Test         | **Not Planned**             |
| What Is The Attack Type?              | **SQL Injection**           |
| Is Traffic Malicious?                 | **Malicious**               |

---

## 3. Indicators of Compromise (IOCs)

- **Source IP:** `167.99.169.17`  
- **ASN:** AS14061 (DigitalOcean)  
- **Country:** United States  

---

## 4. Evidence & Analysis

### VirusTotal Findings
- **5/95 security vendors** flagged the IP as malicious.
- Detections included:
  - Malware  
  - Malicious  
  - Phishing  
  - Suspicious  
- Community score: **-15**  
- Confirms malicious behavior commonly associated with scanning bots and exploited infrastructure.

### AbuseIPDB Results
- Reported **14,914 times**.
- Usage: **Data Center/Web Hosting/Transit**.
- Indicates likely automated attack infrastructure.

### Traffic Characteristics
The captured request contained patterns consistent with SQL Injection, such as:
- `' OR 1=1--`
- `UNION SELECT`
- Database enumeration payloads

These confirm an SQL Injection probe and attempted exploitation.

---

## 5. Impact Assessment

- No data loss or unauthorized access.  
- Attack blocked by existing security controls.  
- No lateral movement or internal compromise detected.  
- No service impact or downtime observed.

---

## 6. Mitigation & Response Actions

1. Verified firewall blocks on the attacking IP address.
2. Confirmed WAF rules blocking SQL Injection signatures.
3. Reviewed application logs—no successful query manipulation detected.
4. Added IP to internal blocklist.
5. Documented incident for SOC recordkeeping.

---

## 7. Recommendations

- Monitor for repeated attempts from similar IP ranges.  
- Ensure application implements input validation, prepared statements, and parameterized queries.  
- Maintain active WAF rules for SQLi detection.  
- Implement rate limiting for repeated malicious requests.  
- Perform periodic penetration testing with focus on SQL Injection vectors.

---

## 8. Conclusion

This incident was a **malicious SQL Injection attempt** originating from a known abusive IP. The attack failed due to proper defensive controls, and no escalation was required. Continued monitoring is recommended to ensure no associated follow-up activity occurs.
---

