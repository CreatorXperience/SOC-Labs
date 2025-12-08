Incident Report: Command Injection Attempt - False Positive

**Incident ID:** SOC167
**Date:** Feb, 27, 2022, 12:36 AM 
**Severity:** High
**Status:** Not Malicious

### 1. Executive Summary

A potential command injection attack was detected by the SIEM, triggering an alert due to the presence of an "LS" command within request parameters.  Investigation determined this to be a false positive. While the initial alert indicated potential malicious activity, further analysis of the associated indicators of compromise (IOCs) and request context revealed no evidence of exploitation or system compromise.

### 2. Incident Details

*   **What:** Potential Command Injection Attempt (False Positive)
*   **Why:** The SIEM detected an alert for an "LS" command within request parameters. Investigation revealed this was a false positive.
*   **Where:** Internal Network
*   **When:** Feb, 27, 2022, 12:36 AM
*   **Who:**  (Information not provided in source data)

### 3. Analysis

The initial alert was triggered by the detection of an "LS" command within a web request parameter.  This raised concerns about a potential command injection vulnerability being exploited. However, further investigation revealed the following:

*   **IOC Analysis (188.114.96.15):**
    *   **VirusTotal:** The IP address 188.114.96.15 has a VirusTotal reputation score of 2, with 0 engines flagging it as malicious and 62 as harmless. Community votes are split (0 malicious / 2 harmless).  The IP is associated with Cloudflare (CLOUDFLARENET) and hosts a certificate for cdnjs.cloudflare.com.
    *   **AbuseIPDB & Cisco Talos:** (No specific findings were provided in the source data, but these tools were used for investigation.)
*   **Contextual Analysis:** (Details regarding the specific request and application are missing, but the conclusion is a false positive.) The presence of the "LS" command was determined to be benign and not indicative of an active attack.

### 4. Indicators of Compromise (IOCs)

*   **IP Address:** 188.114.96.15

### 5. Tools Used

*   VirusTotal
*   AbuseIPDB
*   Cisco Talos

### 6. Remediation

No remediation is required as the incident was determined to be a false positive. However, the following is recommended:

*   **SIEM Rule Tuning:** Review and refine the SIEM rule that triggered the alert to reduce false positive rates. Consider adding context to the rule to better differentiate between legitimate and malicious "LS" command usage.

### 7. Analyst Information

*   **Analyst:** Habeeb



### 8. Conclusion

This incident was classified as **Not Malicious** with a **High** severity due to the initial alert's potential impact.  The investigation successfully determined the alert to be a false positive, and no further action is required at this time. Continued monitoring and SIEM rule tuning are recommended to prevent similar false positives in the future.
