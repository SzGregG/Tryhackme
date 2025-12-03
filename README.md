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
