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

## Network Traffic Analysis (NTA)
NTA is the process of capturing, inspecting and analysing data that travels on a network. It is used to monitor network performance, check on deviations and issues, inspect content of suspicous communication. It helps to detect abnormal or malicious activity, reconstruct how an attack unfolded and verify alerts.
  
### Network Security Monitoring
A network is an organisaed structure where network assets are able to communicate and share resources and able to connect with each other and the world via internet.

**Network Components**
- Endpoints/Workstattions
- File & Database Servers -  organisation's most important asset the data is here
- Application Servers (Web, Email, VPN, etc.)
- Active Directory / Authentication Server -  Manages users, groups and computers and their what they can access
- Routers & Switches
- Firewall / Perimeter Devices

**Network Visibility**  
It is important to have a clear view of devices and activity that happens on the network for analysts to have good detection and effectively monitor network security. This can be achieved by collecting the necessary information from key log sources.  
- **Host-based Logs**
  - Operating System logs - Windows Event logs, Linux syslog, macOS logs. Records of user logons and failed attempt, process creation, service startups etc.
  - Application logs - Logs from software running on host
  - Security Tool logs - Logs from AV software or EDR agents, Host-based Intrusion Detection Systems (HIDS)
- **Network-based Logs**
  - Firewalls - contains records of all connections allowed and denied 
  - (Network-based)Intrusion Detection / Prevention Systems ((N)IDS/IPS) - monitors network looking for known signitures or anomalies
  - Routers & Switches - displays network activity, showing which devices interacted with each other
  - Web Proxies - Records every website user's visit
  - VPNs - Logs devices that connect remotely ot the corporate network, including their location, time etc.
  
Host-based logs come from individual devices on the network, showing what is happening on specivif machines in detail. While Network-based logs shows what is happening between the devices, generated by tools which are on the network monitoring the traffic. Network logs show , source and destination IPs, ports, protocols and actions (allowed or blocked). For effective visibility and network security monitoring both host and network based logs are necessary.  
  
**Network Perimeter**  
It is the barrier that separates an organisation's internal network from the the Internet. All traffic coming from or going to the internet must pass through this point.  
Components of the network perimeter can include:
- Firewalls: Filters traffic between internal and external networks
- Router/Gateways: Routes traffic and enforces access rules
- Demilitarised Zone (DMZ): A special network isolated network segment from the rest of the internal network where servers that frequently interact with external networks are located (e.g.: web, mail and VPN servers)
- Remote Access Gateways / VPNs: Secure entry point for employees working remotely
  
The perimeter is considered the first line of defense against attackers. Security Analysts can monitor the perimeter to seesigns for malicious activity including:  
- Firewall logs for bloacked/allowed connections
- Spot scanning or brute-force login attempts
- Alert unusual outbound traffic for possible exfiltration or malware beaconing

What to look out for when monitoring the network perimeter:
- Look for suspicious patterns
- Repetition from one source to many destination = scanning
- Repetition from one source to one destination = Brute-forcing
- Traffic at perfect regular intervals = malware beaconing
- Look for context. IDS's reason why something has been flagged

### Network Discovery
Attackers perform network discovery to try to understand their target. It is usually the first step in their malicious activities and usually the most often encountered by SOC analysts. Attackers do this to map out organisation's assets that are accessible to the public (aka. attack surface).  
**Attackers goal with discovery:**
- What assets can be accessed by them from the outside?
- What are the IP addresses, ports, OS and services running on the assets?
- What versions are the assets running on? Is there anything that might be vulnerable?

Defender can also perform network discovery, to see how they can reduce the organisation's attack surface.  
  
**Defenders goal with doscovery:**
- Inventory all the assets and make sure they are documented
- Make sure that only necessary IP, ports and services are open and running and everything else is closed
- Ensure vulnerabilities are patched

To reduce false positives/ noise from defensive network disvcovery, known internal scanners (their IPs) can be put on allowed lists.  

There are 4 types of scanning that defenders can face:  
- *External scanning:* This is when the attacker is in their Reconnaissance phase the very first phase/tactic of the MITRE ATT&CK lifecycle. Meaning the attacker does not have a foothold within the network and it is trying to identify opportunities to gain access.
- *Internal scanning:* Done when the scan is done inside the same network. If done by not authorised internal scanner then this mean that the attacker has already managed to gains foothold and would be in the Discovery phase/tactic of the MITRE ATT&CK lifecycle. Performed to scout out potential for lateral movement. This would be a high-severity case which would need immidiate attantion from the defenders.
  
Once the attackers have mapped out the assets they will perform the following scannings  
- *Vertical scanning:* When the attacker scans a single amchine for multiple ports. Done when the particular machine is the target/goal and trying to identifying a vulnerability on it. 
- *Horizontal scanning:* When the attacker scans for the same port accross different destination IPs. This is aimed to identify exposure of machines on a specific port. (e.g.: WannaCry on port 445)

**Scanning Techniques:**
- *Ping Sweep:* Used to identify hosts present and running on a network. Done by sending Internet Message Control Protocol (ICMP) packets to hosts. If the host is online it will respond with anotehr ICMP packet. Since it is very common and easy to do it is often blocked with security tools and is a good baseline to implement as defenders to stop this type of scanning.
- *TCP SYN Scans:* Using the 3 way handshake process of the TCP protocol to establish connections scanners can use it as well by sending the first initial SYN request to hosts. If the host is online and the port is open the host responds with a SYN-ACK packet. This can blend more easily with usual network traffic
- *UDP Scan:* Similar to TCP, the atacker sends a UDP packet. There can be 3 scenarios. The host will either send back an ICMP "port unreachable" reply, which would mean the machine is only but the port is closed. Second scenario can be that there won't be any reponse, in this case the scanner will flag the port open, but this migth not be neccesarily the case. Third case, rarely there might be a reply UDP packet back, meaning the port is open. UDP scan is slow and unrealiable though

### Data Exfiltration Detection
Data exfiltration is the unauthorised transfer of data from an organisation to an external destination controlled by an attacker. It can be either intentional by an insider or through malware or other means by an external actor.  

**Reasons why data exfiltration is done:**
- *Financial Gain*
- *Espionage*
- *Ransomeware & Extortion*
- *Disruption & Sabotage*
- *Persistence & Reconnaissance:* Stolen data helps attackers understand the environment/network for future attacks

**Techniques & Indicators:**
- *Network-based:* e.g.: HTTP/S uploads, S/FTP, DNS tunneling, custom TCP/UDP. Look for large POST requests or cloud uploads in proxy/web gateway logs, spikes in outflowing network traffic, DNS logs (long hostnames, TXT queires)
- *Host-based:* e.g.: Powershell/Invoke-WebRequest, curl/wget, archive creation (zip/rar), use of removable media. Look at EDR (Process Create, File Create and Network connection events), Windows security (4663/4656 object access)
- *Cloud Exfiltration:* e.g.: Drive/Sharepoint external sharing. Look for cloud storage activity and access logs, unusual service-account or IP activity
- *Covert & encoding:* e.g.: DNS tunneling, base64 or other encoding, steganography (placing data into images or audio), splitting files into small requests. Look through DNS logs, proxy logs, many small POST requests
- *Insider & Collaboration tools:* e.g.: Slack/Teams/Dropbox/Google Drive uploads or sharing to external users, compromised employee accounts. Look at audit logs (share events, file downloads) and mail logs
- *General IoAs:* e.g.: Large outbound volume to external IPs, suspicious processes and command lines, many file read events with an outbound connection after. Look at and compare DNS, EDR, Proxy, Firewall and mail server logs.

**DNS Tunneling**
It exploits the fact that the  DNS protocol is typically allowed to pass through networks. Attackers use this to smiggle bytes encoded inside the DNS queries/responses without firewalls or web proxies noticing, sometimes even unfiltered. It is a good disguise as every host usually does DNS lookups and they are frequent making them a perfect tool for attackers to blend in their activity.  

Indicators of DNS Tunneling:
- Many DNS queries sent to a single external domain
- Long subdomain labels or extra lognn query names (60-100+ characters)
- Unusual response behaviour: No responses to DNS queries, or large TCP/UDP fragments for DNS
- Queries at regular intervals (beaconing likely)

### Man-in-the-Middle (MITM) Detection
MITM attacks happen when an attakcer places themselves between two points of a communication attempting to intercept, modify or redirect the traffic between the 2 points. Attackers can use it to steal sensitive data or even to inject malicious content. If weak encryption or authentication is used then machines and organisations are particularly vulnerable to this attack.
  
**Steps of MITM Attacks:**
- *Step 1:* Interception - The attacker places themselves into the path of communication, often by exploiting weaknesses in network protocolsm or by using ARP, DNS, or IP spoofing
- *Step 2:* Manipulation/Decryption:* The attacker tries to access or modify the communication, decrypting encoded data or injecting harmful content e.g.: alterd website responses or fake login forms

**Common MITM Attacks:**
- *Packet sniffing:* capturing unencrypted data packets sent over a network, often on open Wifi
- *Session hijacking:* Stealing and using session tokens to impersonate users
- *SSL Stripping:* Downgrading HTTPS connections to HTTP (which is not secure) to steal and alter data transfer
- *DNS spoofing:* Redirecting website traffic to fraudulent domains by manipulating DNS responses
- *IP spoofing:* Crafting malicious IP packtes that appear to come from a trusted system
- *Rouge wifi-access poing:* Creating fake networks to intercept user traffic

MITM attacks are widely used in the Cyber Kill Chain's Exploitation and Installation phases in their attacks. For Exploitation, attackes exploit the limitations and natural trust given to network protocols. By manipulating protocols like DNS or ARP, attackers can intercept communication channels, damaging integrity and allows eavesdropping and manipulation. For the Installation phase, once the attacker already places themselves in the middle of communication channels, they can use it to control the data stream flowing through it and modify it to deliver malicious payloads.  

**Detecting ARP Spoofing**
ARP (Address Resolution Protocol) spoofing utilises the ARP protocol which maps IP addresses to MAC addresses on a local network. In ARP spoofing, the attacker sends fake ARP replies to deceive devices into thinking that the attacker's MAC address in the default gateway. This allows the attacker to intercept, modify or redirect all the traffic.  

Indicators of ARP Spoofing:  
- *Duplicate MAC-to-IP Mappings:* Multiple MAC addresses caliming the same IP address. Signs of impersonation
- *Unsolicitated APR Replies:* High number of ARP replies, without matching requests
- *Abnormal ARP Traffic Volume:* Large number of ARP packets in short intervals
- *Unusual Traffic Routing:* Trraffic rerouted through the attaccker's MAC
- *Gateway Redirection Patterns:* Multiple destination MACs to the same gateway IP
- *ARP Probe/ Reply Loops:* Many ARP requests with the "Who has x? Tell y" patterns

**Detecting DNS Spoofing**  
DNS Spoofing aka. DNS Cache Poisoning is when the attacker corrupts the DNS and manipulates it to give the wrong IP address to users when they search for a domain. Usually the victim would try to visit a legitimate website, the attacker who is on the local network already can intercept this the DNS query from the victim. Once intercepted the attacker sends a fake DNS reply with the attacker's or another malicious IP address instead that of the bank's. From here the victim machine receives it in their DNS cache and when the victim tries to connect to the bank they instead directly connect to the attacker's server hosting a replica of the desired site.  

Indicators of DNS Spoofing:  
- *Multiple DNS responses to the same query* a legitimate resolver and a forged second response source
- *DNS response from an unexcpected source* - DNS reply arrives from an IP address not associated to the configured resolver
- *Suspiciously short TTL (Time-to-Live) values* - attackers use low TTLs (1-30), keep forged entries short lived
- *Unsolicitated DNS responses* - dns reply appears without prior request

**Detecting SSL Stripping**
SSL (Secure Sockets Layer) stripping is a technique where an attacker intercepts and modifies traffic to prevent TLS (Transport Layer Security) encryption between a client and a server.  
  
Steps of SSL stripping:  
- 1 The victim initiates a HTTPS request to a website
- 2 The attacker intercept the request using ARP spoofing or a rouge access point
- 3 The attacker connects to the website over HTTp but relays the response to the victim through HTTP
- 4 The victim unknowingly interacts over HTTp, exposing data in plaintext which the attacker can see

Indicators of SSL stripping:  
- Initial request vs response: Request is in HTTps (port 443), but the response comes back in HTTP (port 80)
- Redirects /Link Reqriting: Redirects that persistently direct HTTPS request to an HTTP resource
- Certificate Errors: the intitial TLS/SSL handshake might fail or display a self-signed certificate

## Web Security Monitoring
The possiblity of web applications has significantly has grown and they have become a very popular and efficient and with more advantages compared to their on desktop counterparts. The more qidespread use also gives more opportunities to attackers, and they are now a very common entry point ass they are always available and exposed.  
  
**Risks with web applications:**  
- *For Owners:*
  - Your web app is always only and needs 24/7 security
  - Anyone can access your app at any time
  - Having to contanstly stay up to data with many emerging threats
  - Have to secure all user's data
- *For Users:*
  - Your data is stored on the web app
  - If your browser is hacked then all other accounts is at risk
  - Potential identity theft and financial loss in case of a breach
  - Privacy can be compromised
  
Users interact with websites through a request response cycle to receive and send materials. Attackers abuse this for various thrings, including overwhelming servers with requests, bypassing access controls or even to get servers to execute malicious commands. Web servers are inbetween users and applications. When a user send a request it goes to the server first as a result they are common targets as well for attackers. Common webservers include: Apache (for simple websites), NGINX(for high-performance web apps e.g.: Netflix, Github, Airbnb), Internet Information Services (IIS)  

**Web App Security Best Practices**  
  
*For the application:*
- Secure coding - don't use insecure funtiomns, remove sensitive info and make sure errors are handled properly
- Input Validation & Sanitisation - do it to user input to avoid injection attacks
- Access Controls - restrict access based on user roles
  
*For the web server:*
- Logging - maintain a detailed record of all the web requests with access logs
- Web Application Firewall (WAF) - Filter and block harmful traffic with defined rules
- Content Delivery Network (CDN) -  reduce direct exposure to the server and use integrated WAF
  
*For the Host Machine (the environement hosting the app and the server):*
- Least Privilage - use low-privilage users for services
- System Hardening - Disable unnecessary services and close unuesed ports
- Antivirus: Add enpoint protection which blocks malware

*For All 3:*
- Strong Authentication - make sure only the required people can access your code
- Patch Management - Ensure everything is up to date e.g.: app dependencies, web server, machines

**Web Security Defensive Tools**  

*Content Delivery Network (CDN):*
CDNs serve and store cached data from servers closer to the user to reduce latency. Besides helping with latency, they also serve as a buffer between the use and the web server thus increasing security.  

Benefits of CDNs:
- IP masking - hides the server of the original web server, making it harder to be targeted by hackers
- DDoS Protection: CDNs can absorb large volumes of traffic, mitigating against DoS attackes
- Enforced HTTPS: Encrypted comms via TLS is enforced by CDNs normally
- Integrated WAF - Most CDNs have integrated WAFs

*Web Application Firewall (WAF):*  
WAFs inspect incoming HTTP traffic and block or log potentially maliciouius requests based on security rules. There are cloud based (placed in front of the server), host-based (software directly on the web server), and network-based(hardware or vitual tool on the network perimeter) WAFs. WAFs have different type of detection capabilities: Signature-based, behaviour/heuristic based, Anomaly & behavious analysis, Locationa and IP filtering etc.  

*Anticirus (AV):*  
They can help detect maliciosu file uploads with their signature based detection. Other tools / layers are still needed though to complement AV and have a good defense in depth.

### Detecting Web Attacks

**Client Side Attacks**  
They target using weaknesses in the user's behaviour or on their device. They aim to exploit browser vulnerabilities or trick the user into doing something unsafe. SOC team's tools have little to no visibility on what happens in user's browser and client side attacks don't tend to generate suspicious HTTP requests. Requires extra browser-side security controls or endpoint monitoring to detect them.

Common Client side attacks:
- *Cross-Site Scripting (XSS):* A malicious script is run on a trusted website and executed in the user's browser. When visitors load the page the script runs inside their browser, enabling attackers to steal cookies or session data
- *Cross-Site Request Forgery (CSRF): The browser is tricked into sending unauthorised requests on behalf of the trsuted user
- *Clickjacking:* Attackers overlay invisibale elements on top of legitimate content, making users beleive they are interacting with something safe

**Server Side Attacks**  
These attacks depend on finding vulnerabilities in the web server, the web app's code or any other infrastructure which supports the web app. In this case there is more trail left which defenders can follow as the servers logs every web request sent to a web app. The requests also travel accross the network so network traffic can highlight suspicious activity.   

Common Server side attacks:
- *Brute-force:* repeated attempt of different usernames and passwords to gain access to an account
- *SQL Injection:* attacks the data base. Happens when applications accept unchecked and sanitised user input in field where attackers can inject SQL scripts allowing them to access and modify data in the database.
- *Command Injection:* Where as SQL injection was exploiting data bases, this targets servers

### Detecting Web Shells
Web shells are a technique used by attackers to gain a foothold on target systems. They allow remote access, enabling other malicious actions to be taken. Web shell is a malicious program uploaded to a target web server, which allows the attacker to execute commands remotely. As a tactic they are considered both an initial access and a persisitence tactic and can be used for several stages in the cyber kill chain.  
In order for the attacker to successfully upload and run a web shell they need to initially find and exploit a file upload vulnerability, misconfiguration or have gain access to the system already. Most common vulnerability is failure to validate the file type/extension/content or destination allowing easy upload of malicious files.
