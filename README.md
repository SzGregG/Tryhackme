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

### Alert Handling  
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

### Resources which can help SOC Analysts  
- *Identity Inventory:* A catalouge of company employees (users), services (machines), and their details like contacts and roles in the company. Sources of identities can be Active Directory, HR Systems, Cloud alternatives of AD (e.g.:SSO providers like Okta or Google Workspace), or other custom solutions  
- *Asset Inventory:* list of all computing resources within the company. Sources of assets can be Acctive Directory, SIEM or EDR, MDM(Mobile Device Management) Solution or once again custom  
- *Network Diagrams:* a visual schema of existing locations, subnets and their connections. Helps to place alerts on the network and see what can be affected or targeted.  
- *Workbooks:* aka playbook, runbook or workflow. It is a document with a structured plan with steps that needed to be followed to investigate and tackle threats efficiently.

### Common SOC Metrics  
- *Alert Counts:* AC = Total Count of Alerts Received. Measures the overall load on the SOC team
  - Too many per analyst can be too much strain, but very low numbers can also suggest detection is not working well
- *False Positive Rate:* FPR = False Positives / Total Alerts. Level of noise in alerts
  - Very high FPR can lead analysts to be less vigilant. Can fine tune detection rules to catch less normal activity and reduce FPR
- *Alert Escalation Rate:* AER = Escalated Alerts / Total Alerts. Experience of L1 Analysts
  - Ideal number should start from less that 50% anything lower is better. You don't want your L1s to be too overconfident
- *Threat Detection Rate:* TDR = Detected Threats / Total Threats. Reliability of the SOC Team
  - Should always be 100%
- *Mean Time to Detect (MTTD):* Average time between the attack and its detection by SOC tools
- *Mean Time to Acknowledge (MTTA):* Average time for L1 Analyst to start triage of a new alert
- *Mean Time to Respond (MTTR):* Average time taken by SOC to actually stop the breach from spreading

## SOC Solutions
### EDR
Endpoint Detection and Response is a host-only security solution that monitors, detects and responds to threats at endpoints. It can tackle advanced threats and no matter where the endpoint is, local or remote. EDR can detect threats that an Antivirus might miss.
  
**Endpoint Features**  
- *Visibility:* EDRs provide a great range of visibility. Collecting data from data which includes, process modifications, registry modifications, network connections, file and folder modifications, user actions etc. Historcal data and process trees as well.
- *Detection:* Uses a combination of signiture and behaviour based detections alongside machine learning capabilities. It can also detect fileless malware in memory. It is possible to assign custom IOC(indicators of comprimise) to be detected
- *Response:* Analysts can respond to threats easily through the central EDR console, managing different actions like isolate endpoint, terminate processes, connect to host and excute actions remotely etc.

**EDR Components**
- *Agents:* agents are what is deployed on endpoints and report back to the central EDR console. They can be also referred to as sensors. They monitor all activities and any data (aka. **telemetry**) collected about the activities is sent to the EDR Console.
- *EDR Console:* it is where all the data sent from various EDR agents is linked together and analysed with the use of logical rules and machine learning algorithms (MLAs). The data collected is then compared against threat intelligence data as well. If anything is detected the console creates an alert, also assigning a severity to it.

**EDR Detection Capabilities**
- *Behavioral Detection:* not just matches signitures but looks at the behaviour of files
- *Anomaly Detection:* EDR is aware of the standard behaviour of endpoints. Activity which mismatches the standard will be flagged. Can cause false positives but with the full contect that EDR provides analysts can deal with it quickly. In case of an malicious activity, the endpoint's behaviour always deviates from standard.
- *IOC matching:* Indicators of Compromise are known by EDRs as threat intelligence is integrated into them. If any activity matches that of an IOC the EDR flags it
- *MITRE ATT&CK Mapping:* EDR not only flags malicious activity but it also highlights the stage that the activity was at on the MITRE Tactics and Techniques map
- *MLAs:* Advanced threats try to pose normal and evade defenses. MLA models trained with large datasets of normal and malicious behaviour can filter out and detect even complex attacks and patterns

**EDR Response Capabilities**
Response can be both automated or manual. Including:
- *Isolate Host:* Can isolate an endpoint from the network to contain attacks. Preventing lateral movement
- *Terminate Process:* Can be done if isolation is not necessary, especially if the endpoint is needed for key business operations and isolation would be more harmful. Have to be careful to not terminate legitimate processes
- *Quarantine:* Can quarantine malicious files that enter an endpoint. Moving it to a separate location where it cannot be executed. From here it can be reviewed to either restore or remove it.
- *Remote Access:* Analysts are able to access the shell of all endpoints through the EDR. Required when the automated response of the EDR is not enough, and more specific or custom actions or data are needed.
- *Artefacts Collection:* Analysts can extract data remotely from endpoint for forensic investigation (e.g.: Memory Dump, Event Logs, Specific Folder Contents, Registry Hives)

### SIEM
Security Information and Event Management systems are a key security solution that collects logs from all the different sources, standardises, and finally correlates them for analysts and detects malicious activity using rules. Log sources can be divided into 2 types:  
- **Host-Centric Log Sources:**
  - User accessing a file
  - User attempting to authenticate something
  - Process execution
  - Process adding/editing/deleting a registry key value
  - Powershell Execution
- **Network-Centric Log Sources:**
  - SSH connection
  - A file being accessed through a File Transfer Protocol (FTP)
  - Web traffic
  - User accessing the company's resources through Virtual Private Network (VPN)
  - Network file sharing activity
  
**Features of SIEMS**
- *Centralised log collection* - Collects all the logs generated on all the systems (e.g.: endpoints, servers, firewalls etc.) in one place
- *Normalisation of Logs* - Raw logs from different sources are in different formats. SIEMs standardises logs by breaking them down into different fields to make them easier to understand and go through
- *Correlation of Logs* - Finds connection between different individual logs from different sources to give a bigger picture and see patterns
- *Real-time Alerting* - SIEMs run all the activity it processes against rules determined either by default or custom by the SOC team. If one if the rules are triggered then the analysts are alerted straight away
- *Dashboard and Reporting* - Dashboard is where all the data is presented to the analysts after it was standardised. From here all the information can be reviewed and analysed for an investigation.

### SOAR
Security Orchestration, Automation and Response (SOAR) is a tool that combines all other tools. SIEM, EDR, Firewalls and other tools are put into one unifiied interface for analysts to use without having to switch. In addition it also has ticketing and case management features, with which analysts can document, follow and remedy incidents. SOAR mitigates or even eliminates issues for SOC teams such as alert fatigue, manual processes, disconnected tools and lack of analysts.
  
**SOAR Capabilities**
- *Orchestration:* Traditionally to analyse an alert, analysts had to swithc between different tools, slowing down processes this way. SOAR combines these tools together into one interface. It also has predefined playbooks which have a step-by-step plan that the SOAR would follow to investigate an alert. With their being different playbooks for specific alerts and multiple options based on results of invastigations.
- *Automation:* The playbooks mentioned under Orchestration can be automated and followed by the SOAR to carry out the investigation. Significantly reducing the workload and the processing time of alerts for analysts.
- *Response:* The automation enables the SOAR to respond to attacks by following the playbook, carrying out the action defined in the playbook (e.g.: disable user in the IAM) and open a ticket and put the necessary information in it.
