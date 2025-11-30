
# General Introduction: INE eEDA Enterprise Defense Administrator Pro Certification

This professional certification program, led by **Brian Olliff, Defensive Engineering Instructor**, is designed to equip security professionals with the comprehensive knowledge and practical skills necessary to defend an enterprise environment effectively. The overall goal of the course is to reduce security risk by minimizing the attack surface through the use of tools, techniques, and best practices. This involves proactively developing and enforcing security plans and procedures.

## Core Objectives

The primary learning objective is to provide the expertise required to reduce system vulnerability by implementing strong technical and organizational controls. This process includes removing extra functions and applications, disabling unnecessary services, and changing default passwords and accounts.

The curriculum is structured around foundational areas of enterprise defense and security operations:

| Pillar | Focus |
| :--- | :--- |
| **I. System Hardening** | Implementing baselines and security controls across diverse devices (Windows, Linux, network equipment, IoT) to minimize attack vectors. |
| **II. Identity & Access Management (IAM)** | Establishing strong authentication and authorization protocols, managing credentials securely, and enforcing the IAM lifecycle (Provisioning, Review, Deprovisioning). |
| **III. Secure Architecture & Engineering** | Designing networks using principles like Defense in Depth and Zero Trust, securing the perimeter, implementing network segmentation, and managing endpoints. |
| **IV. Logging & Monitoring** | Utilizing security sensors (host and network), centralizing logs (SIEM), and leveraging automation (SOAR) for real-time analysis and incident detection. |
| **V. Vulnerability Management (VM)** | Establishing systematic processes for identifying, scoring (CVSS), prioritizing, and remediating weaknesses in the infrastructure. |
| **VI. Governance, Risk, and Compliance (GRC)** | Aligning security practices with business goals, managing risk appetite, and ensuring adherence to mandatory (HIPAA, GDPR) and voluntary (NIST, CIS) frameworks. |

---

## Key Modules and Topics

### 1. Introduction to Cyber Security Hardening
Hardening involves applying tools, techniques, and best practices to reduce vulnerability.

*   **Concepts & Frameworks:** Students will understand the use of the NIST Cyber Security Framework (CSF) and NIST Special Publication 800-53, as well as guidelines from the Center for Internet Security (CIS) and CISA/US-CERT.
*   **System Hardening:** Detailed practices are covered for various systems, including Windows Servers and Workstations (using GPOs, LAPS, and BitLocker Encryption), Active Directory (managing privileged accounts and domain controllers), and Linux (using tools like SELinux and Fail2ban).
*   **Network Device Hardening:** Techniques include using secure management protocols like **SSH instead of Telnet** and **SNMPv3**, changing default passwords, and disabling unnecessary services.

### 2. Identity & Access Management (IAM)
IAM focuses on the four components of security access: Identification, Authentication, Authorization, and Accounting (AAA).

*   **Authentication Types:** The course explores knowledge-based (passwords/passphrases), ownership-based (tokens, smart cards), and biometric authentication. **Multi-Factor Authentication (MFA)** is emphasized for sensitive access and remote connections.
*   **Password Management:** NIST 800-63B recommendations are key, advocating for a minimum of 8 characters (max 64), allowing all ASCII and Unicode characters, and advising against requiring arbitrary password changes.
*   **Authorization Models:** Coverage includes Discretionary Access Control (DAC), Mandatory Access Control (MAC), and the preferred **Role-Based Access Control (RBAC)**, which uses roles instead of assigning permissions directly to individuals.
*   **Access Concepts:** The principle of **Least Privilege** (granting only necessary access) and the concept of **Just-in-Time (JIT) access** for temporary elevation of privileges are explored.

### 3. Security Engineering and Change Management
Security engineering is a technical role involving developing and configuring security controls proactively.

*   **Security Domains:** The course differentiates security efforts across the **Perimeter** (firewalls, DMZ, Email Security), the **Network** (segmentation, ACLs, NAC), and the **Endpoint** (Least Privilege, AV/EDR, Encryption).
*   **Change Management (CM):** CM is a structured plan and process for introducing changes, critical for maintaining accountability and tracking the environment. Changes are categorized as Planned, Break/Fix, or Emergency.
*   **CM Process:** The lifecycle involves Change Introduction, Research & Documentation, Review, Implement, and Learn. Changes should be tested in a Test/Development environment before Production implementation.
*   **GRC Fundamentals:** Governance ensures alignment with business goals; Risk identifies threats and opportunities; and Compliance ensures adherence to laws and regulations (e.g., HIPAA, PCI-DSS, GDPR).

### 4. Security Sensors & Logging
Logs are critical for identifying almost any type of security issue, providing historical and forensic data.

*   **Sensors:** Security sensors collect data from devices or the network. Types include **Host Sensors** (Windows Event logs, EDR software) and **Network Sensors** (Network Tap, SPAN ports, IDS/IPS systems).
*   **Centralized Logging:** Centralizing logs into a single destination significantly eases auditing, facilitates analysis and automation, and protects logs from attackers who frequently attempt to delete them.
*   **Automation:** **SIEM (Security Information & Event Management)** systems ingest and normalize logs, performing real-time analysis and correlation. **SOAR (Security Orchestration, Automation, & Response)** platforms extend this capability by automating security tasks and incident response activities.

### 5. Vulnerability Management (VM)
A vulnerability is a weakness that could be exploited by a threat source.

*   **Vulnerability Scanning:** Scanners are used to inventory systems, perform port checks, and compare system information against known weaknesses. Scans can be **Authenticated** (providing better data) or Unauthenticated, and Internal or External.
*   **Scoring and Research:** The **CVSS (Common Vulnerability Scoring System)** is the standard for assigning scores (Non, Low, Medium, High, Critical) to prioritize remediation efforts. Key resources for information are **CVE (Common Vulnerabilities and Exposures)** and **NVD (National Vulnerability Database)**.
*   **VM Operations:** VM requires a defined, repeating cycle integrated with Change Management, covering scoping, inventory, scanning, reporting, prioritization, and remediation testing.

### 6. Secure Architecture Design and Business Operations
Secure Architecture involves designing and configuring the infrastructure with security in mind from the start.

*   **Design Principles:** Critical principles include the **CIA Triad** (Confidentiality, Integrity, Availability), **Defense in Depth** (multiple security layers), **Zero Trust** (trust but verify), and **Privacy by Design**.
*   **Threat Modeling:** Techniques like the **Cyber Kill Chain** (seven stages of an attack) and the **MITRE ATT&CK Framework** (detailed tactics and techniques) are used to identify threats and develop countermeasures.
*   **Disaster Recovery (DR) & Business Continuity (BC):** Planning includes defining backup types (Full, Differential, Incremental) and establishing recovery sites (Hot, Warm, Cold sites) to ensure timely recovery from major disruptions.
*   **Evaluating Networks:** When assessing an existing network, the structured process involves verifying the asset inventory, performing risk and vulnerability assessments, reviewing existing controls, prioritizing changes, and implementing them through the Change Management process.

## Certification Examination (eEDA)

The Enterprise Defense Administrator Pro (eEDA) examination consists of independent questions (multiple choice, scenario-based) and a **hands-on practical portion in a lab environment**.

Candidates should practice skills in the EDA Sandbox Environment, which typically includes Windows (with Active Directory), Linux, and network devices, practicing commands, firewall rules, and reviewing vulnerability scan reports. During the exam, resources such as command documentation and vendor documentation are permitted, but collaborating with other people is strictly prohibited.