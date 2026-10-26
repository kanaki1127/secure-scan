COMPLIANCE_MAP = {
    "CWE-89": {
        "name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        "owasp": "A03:2021 - Injection",
        "pci_dss": "6.2.4",
        "remediation": "Use parameterized queries or prepared statements instead of concatenating user input into SQL commands.",
    },
    "CWE-79": {
        "name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        "owasp": "A03:2021 - Injection",
        "pci_dss": "6.2.4",
        "remediation": "Contextually encode all untrusted output before rendering it in web pages and use Content Security Policy.",
    },
    "CWE-78": {
        "name": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
        "owasp": "A03:2021 - Injection",
        "pci_dss": "6.2.4",
        "remediation": "Avoid invoking shell commands with user input, or use safe APIs that pass arguments without shell interpretation.",
    },
    "CWE-22": {
        "name": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
        "owasp": "A01:2021 - Broken Access Control",
        "pci_dss": "6.2.4",
        "remediation": "Validate and sanitize file paths against an allowlist and resolve canonical paths to ensure they remain within the intended directory.",
    },
    "CWE-798": {
        "name": "Use of Hard-coded Credentials",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "pci_dss": "6.2.4",
        "remediation": "Store secrets in secure external vaults or environment variables rather than embedding them directly in source code.",
    },
    "CWE-327": {
        "name": "Use of a Broken or Risky Cryptographic Algorithm",
        "owasp": "A02:2021 - Cryptographic Failures",
        "pci_dss": "6.2.4",
        "remediation": "Use modern, standard, and vetted cryptographic algorithms and libraries instead of deprecated or proprietary ciphers.",
    },
    "CWE-502": {
        "name": "Deserialization of Untrusted Data",
        "owasp": "A08:2021 - Software and Data Integrity Failures",
        "pci_dss": "6.2.4",
        "remediation": "Avoid deserializing untrusted data, or use safe data serialization formats like JSON with strict schema validation.",
    },
    "CWE-611": {
        "name": "Improper Restriction of XML External Entity Reference",
        "owasp": "A05:2021 - Security Misconfiguration",
        "pci_dss": "6.2.4",
        "remediation": "Disable external entity resolution (DTD/XXE) in all XML parser configurations.",
    },
    "CWE-918": {
        "name": "Server-Side Request Forgery (SSRF)",
        "owasp": "A10:2021 - Server-Side Request Forgery",
        "pci_dss": "6.2.4",
        "remediation": "Validate and restrict outgoing URLs against a strict allowlist of destinations and block access to private/internal IP ranges.",
    },
    "CWE-352": {
        "name": "Cross-Site Request Forgery (CSRF)",
        "owasp": "A01:2021 - Broken Access Control",
        "pci_dss": "6.2.4",
        "remediation": "Use anti-CSRF tokens for state-changing requests and enforce SameSite cookie attributes.",
    },
    "CWE-284": {
        "name": "Improper Access Control",
        "owasp": "A01:2021 - Broken Access Control",
        "pci_dss": "6.2.4",
        "remediation": "Enforce principle of least privilege and verify permissions on every access attempt on the server side.",
    },
    "CWE-20": {
        "name": "Improper Input Validation",
        "owasp": "A03:2021 - Injection",
        "pci_dss": "6.2.4",
        "remediation": "Validate all incoming data against strict allowlists of acceptable formats, types, and lengths before processing.",
    },
}


def lookup(cwe_id: str) -> dict | None:
    """Case-insensitive lookup. 'cwe-89' and 'CWE-89' both match.
    Returns None if not found."""
    if not isinstance(cwe_id, str):
        return None
    normalized = cwe_id.strip().upper()
    return COMPLIANCE_MAP.get(normalized)
