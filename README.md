# Tryhackme

### Intro  
I have completed previously the SOC Level 1 learning Path on Tryhackme this October, landing me in the top 2% of users. The learning path however, has just been reworked by Tryhackme so I decided to document my learning and take notes here in preparation for me to take the SAL1 exam.


## Blue Team Introduction
**Companies can have different security teams:**  
- *Read Team:* Pentesters, ethical hackers, people who focus on attacking and try to identify security issues through offensive approach e.g: attacking systems
- *GRC Team:* Stands for Governance Risk and Compliance, this team ensures that company policies are in line of regulations and industry standards e.g: GDPR, PCI DSS
- *Blue Team:* Defensive security personnel, they focus on implementing defensive measures, monitoring systems and respond to incidents. Includes SOC Analysts, Engineers, incident responders

**Blue Team types:**  
- *Security Operations Center (SOC) Team:*
  - L1 Analyst: Junior member who processes incoming security alerts, passing on complex ones to L2 Analysts
  - L2 Analyst: More experienced members who look at advances attacks and incidents
  - Engineers: Specialists in setting up and managing security tools e.g: EDR ,SIEM ,firewalls
  - Manager: The one managing the SOC team
- *Responsabilities:* Operates 24/7, creation of detection rules, investigates security alerts, log collection and monitoring, writing reports

- *Cyber Incident Response Team (CIRT):*
  - Digital Forensics: Analyses evidence left behind on machines in disk and memory
  - Threat Intelligence: Conducts research about cyber security threat and attacker's TTP: Tactics, Techniques and Procedures
  - Threat Hunter: Proactively looks for threats and analyses systems and data to find anything that might have circumvented exsting security controls and detections
  - Malware Analyst: Analyses malicious software, how it works, what it does and where it could have originated from
  - Manager: Manages the team and keeps in contact with other important company stake holders e.g: Board, CEO, IT, PR
- *Responsabilities:* They come in when shit hits the fan and SOC needs more expertise

### Human Attack Vectors  
Humans are frequently targeted as they are usually the weak-link among all the defences. They can provide access to systems, data and more with a relatively low barrier to entry when it comes to exploiting them vs well configured systems. Attackers aim to manipulate people to reach what they need, this tactic is referred to as social engineering. One of the most well-known social engineering attacks is phishing, however there are many others like tailgating, shoulder surfing, and watering hole attacks as an example.
  
These attacks use human emotions and psychology to influence people, by using the following:
  - Sense of urgency
  - Scarcity
  - Authority
  - Curiosity
  - Fear
  
Solutions to reduce human attack vectors are to work on mitigation and detection. Mitigation by reducign chances of an attack succeeding through awareness trainings and deploying tools against phising. Detection by having a good SOC team on hand when someone does click that malicious link so they can investigate and handle it straight away. Mitigation also reduces the load on your SOC team and helps your company be more secure.  
*Mitigation solutions include:*
- Anti-phising solutions
- Antivirus or EDR solutions
- Security awareness trainings
- "Trust but verify" - not just trust something but also take action to confirm the information and its accuracy

### System Attack Vectors
Systems can be attack vectors as well if not configures properly. This system can be anything: laptops, servers, websites. These systems could be breach through various means: misconfigurations like weak passwords, vulnerabilities, malicious USB, supply chain attack e.g: Solar Winds  
Vulnerabilities need to be discovered to address them. If an attacker discovers a vulnerability before anyone else and exploits it, then it is called a zero-day attack. Vulnerabilities once discover get a Common Vulnerabilities and Exposures (CVE) number. To address a vulnerability/CVE is to patch (an update fix) the software provided by the vendor.  
While waiting for a patch by the vendor you can mitigate risk by:
-  Restricting system access to only trusted IPs
-  Apply temporary measures provided by the vendor
-  Block known attack patterns with a IPS or WAF
  
Misconfigurations on the otherhand happens not because something is an error in the system but because it was badly set up. These include weak passwords, improprly set up security controls.  
Mitigating misconfigurations:
- Penetration Testing, using ethical hackers
- Vulnerability scans: running tools periodically which detect weak passwords or out of date software
- Configuration benchmarks and audits

## SOC Team Internals
Logs get created by systems constantly and then get fed into security tools like a SIEM, which can get millions of logs daily. Alert on the other hand are created when a specific event or sequence of events occur, this way highlighting logs that need review and thus help SOC teams not requiring them to manually look through every single log.  
**Alert Management Platforms:**  
- SIEM (Security Information and Event Management) System - Splunk ES, Elastic (ELK)
- EDR/NDR (Endpoint/Network Detection and Response - Microsoft Defender, CrowdStrike
- SOAR (Security Orchestration, Automation and Response) System - Splunk SOAR, Cortex SOAR
- ITSM (Information Technology Service Management) - Jire, TheHive
  
**Alert Properties**  
Alerts can have various properties but they tend to share the main ones. There are:  
- Time - alert creation time
- Name - Summary of what happened, based on rule name that got triggered
- Severity - shows how urgent the alert is, set by engineers through the rules initially but can be altered by analysts
- Status - shows if it is WIP or done
- Verdict - aka classification, e.g.:Positive, or false positive
- Assignee - who got assigned to look at it
- Description - explanation of what the alert was about
- Fields - comments and values of why the alert got triggered

Best practices: - start with critical alerts and work your way down with severity, after severity, go by time starting with the oldest one

**Alert Handling**  
- Reporting: Before closing down or escalating an alert, documentation might be needed. Writing down the investigation in detail and all relvant evidence.
- Escalation: True Positives if needed based on procedures can be escalated to L2 Analysts. In this case reports are useful to get an initial idea of what the analyst is dealing with.
- Communication: Communication might be needed with other departments to cross check details and events
  
**Alert Reporting**  
*Puprose:*
- Provide context for escalation - makes it easy to understand by others and saves time for L2 analysts to act
- Save findings for the records - logs are deleted after a while but alerts are kept indefinitely so it can be revisited anytime and understood if everything is written inside
- Improve investigation skills - boost skills and your understanding
  
*Report Format:*  
- Who? - which user logs in /runs command /downloaded a file
- What? - action or event sequence was performed
- When? - when did the suspicious activity start and end
- Where? - which device, IP or website was involved in the alert
- Why? - the reasoning for you final verdict (why true or false positive?, very important)

**Alert Escalation**  
*Recommended in case:*
- Alert is indicator of a major attack, requiring deeper investigation or DFIR
- Remediation actions are needed like malware removal, host isolation, or password resets
- Communication with customers, law enforcement, management or partners is required
- If you don't fuly understand the alert and need help from a senior analyst

**Resources which can help SOC Analysts**  
- *Identity Inventory:* A catalouge of company employees (users), services (machines), and their details like contacts and roles in the company. Sources of identities can be Active Directory, HR Systems, Cloud alternatives of AD (e.g.:SSO providers like Okta or Google Workspace), or other custom solutions  
- *Asset Inventory:* list of all computing resources within the company. Sources of assets can be Acctive Directory, SIEM or EDR, MDM(Mobile Device Management) Solution or once again custom  
- *Network Diagrams:* a visual schema of existing locations, subnets and their connections. Helps to place alerts on the network and see what can be affected or targeted.  
- *Workbooks:* aka playbook, runbook or workflow. It is a document with a structured plan with steps that needed to be followed to investigate and tackle threats efficiently.


