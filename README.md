# wazuh-SIEM-with-ubuntu-

This project demonstrates a practical implementation of Wazuh SIEM on Ubuntu. Below are the key findings and tasks completed during this setup:

**Key Highlights:**

Installing and Deploying Wazuh
Deploying Wazuh Agents on Ubuntu and Windows
File Integrity Monitoring in Wazuh
Detecting the Execution of Malicious Commands
Detecting and Blocking SSH Brute-Force Attacks




**Installing and Deploying WAZUH**

First, I installed Wazuh in Docker using the official Wazuh documentation and followed the guided installation:

🔗 Wazuh Installation Guide: https://documentation.wazuh.com/current/deployment-options/docker/docker-installation.html

Next, I downloaded and imported the Ubuntu VM and deployed Wazuh in Docker.

WAZUH GUI

![1](https://github.com/user-attachments/assets/265396df-1946-4bcd-9e3c-97a3fca581a4)

![2](https://github.com/user-attachments/assets/56363e0c-6162-460d-919c-9fdda464d02c)


**Deploying WAZUH in Ubuntu and Windows**

After setting up Wazuh, I deployed agents on both Ubuntu and Windows to collect and analyze security events. The screenshot below shows the successful deployment:

**Deploying  Agents in Ubuntu and Windows**
![3](https://github.com/user-attachments/assets/a5cbaa1c-e7b5-4b92-a23f-2141e2bb446d)

next we will deploy the WAZUH in powershell using the given script by wazuh

![4](https://github.com/user-attachments/assets/1e48273f-618b-4b88-9a55-c3daaf6ae5bf)







**File Integrity Monitoring in Wazuh**

The Wazuh logs indicate file integrity monitoring (FIM) alerts, highlighting changes in critical system files. A new file, 0015-ossec_rules.xml, was added in the ruleset/rules directory, triggering Rule 554 with a severity level of 5. Additionally, Wazuh detected a change in /root/.lesshst, suggesting user activity or a potential unauthorized modification, flagged under Rule 550 with a severity level of 7. These alerts play a crucial role in identifying unauthorized file changes, potential security threats, or compliance violations, ensuring system integrity and security.
 
![File system intergrity 1](https://github.com/user-attachments/assets/6916dc19-27ad-48a4-aba9-8ab46388c96f)



![Screenshot 2025-02-24 115928](https://github.com/user-attachments/assets/4844ef6c-61d1-4b26-9a31-3668274a827a)



**Detecting the Execution of Malicious Commands**

The images depict a process of monitoring and analyzing system audit logs to detect and execute potentially malicious commands. The first two images show audit log entries from a monitoring tool that captures system events, specifically focusing on the execution of the netstat command. The logs display details such as the user ID, command path, execution status, and file permissions. The third image shows the netstat command being run in a terminal, listing active network connections, sockets, and associated processes. The final image captures commands executed in a Linux terminal, including editing configuration files and restarting the Wazuh agent, an open-source security monitoring tool. Additionally, auditctl -R /etc/audit/audit.rules is used to reload audit rules, indicating an attempt to enhance system monitoring by tracking specific activities for security analysis.


![Detecting and executing malicious command 1](https://github.com/user-attachments/assets/6fd2594b-0e2b-4b5f-bd36-14df59f5ee7e)

![Detecting and executing malicious command 2](https://github.com/user-attachments/assets/f4e90379-17de-4ea3-a1b4-3ac40e04fc18)

![Screenshot 2025-02-24 181050](https://github.com/user-attachments/assets/4a949baf-b4be-4b1f-9ce0-3567469edbbc)

![Screenshot 2025-02-24 181101](https://github.com/user-attachments/assets/3eaf7ac8-7248-4c1e-9479-315ffab2305b)


**Detecting and Blocking SSH Brute-Force Attacks**


In this task, I used Kali Linux as the attacker machine and Ubuntu VM as the victim machine, with the Wazuh agent monitoring and blocking unauthorized SSH login attempts.

![ssh attack](https://github.com/user-attachments/assets/c211f7b5-22ef-4923-ba0e-f1336daa6926)

The attacker machine continuously attempts to brute-force SSH credentials on the victim machine. Wazuh monitors these repeated failed login attempts in real-time and triggers an alert when it detects suspicious activity.
![ssh monitoring](https://github.com/user-attachments/assets/c18d80e8-9610-4531-9b4c-2fd5674fd419)

As seen in the logs, Wazuh successfully detects the brute-force attack and generates alerts based on predefined rules. Once the threshold is exceeded, Wazuh can take mitigation actions, such as blocking the attacker's IP address, preventing further intrusion attempts. This demonstrates the effectiveness of Wazuh in real-time security monitoring and intrusion prevention.








![Screenshot 2025-02-24 191125](https://github.com/user-attachments/assets/efeec537-4e31-4cc4-8497-44b3c0f85fff)

The WAZUH monitoring system has identified security vulnerabilities in the tracked machines, specifically affecting the openssh-client and gnupg packages. The detected CVEs include CVE-2025-26465 and CVE-2025-26466 on the Ubuntu system, both of which have been resolved, while CVE-2019-13050, a high-severity vulnerability affecting gnupg on the RHEL7 system, remains active. This highlights the importance of continuous vulnerability assessment and timely patching to mitigate security risks.


![Screenshot 2025-02-24 191605](https://github.com/user-attachments/assets/f29efb77-4df8-41a0-9184-669e7ef8800f)

The brute-force attack on the SSH service has been mapped to MITRE ATT&CK tactics and techniques, specifically under Credential Access and Lateral Movement. The identified techniques include Password Guessing (T1110.001) and SSH-based lateral movement (T1021.004). These classifications provide a structured approach to understanding the attacker's methods, enabling better detection, prevention, and response strategies to mitigate future threats.

