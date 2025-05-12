# Soclab1
Overview

This lab consolidates multiple cybersecurity experiments to simulate, analyze, and mitigate attacks on a Cyber-Physical System (CPS) or IoT environment. It covers:
SSH Brute-Force Attack Simulation: Perform an SSH brute-force attack using Hydra and mitigate it with Fail2Ban.
Wireshark Traffic Analysis: Analyze a packet capture (pcap) file to identify a Man-on-the-Side (MotS) attack.
Firewall Configuration: Use iptables to block advanced Nmap scans (SYN and Xmas scans).
Intrusion Detection with Snort: Configure Snort to detect ICMP and SSH traffic.
VPN Setup with OpenVPN: Establish a secure TLS-based VPN tunnel between two VMs.
The lab is conducted on two Kali Linux VMs in VirtualBox, with VM1 acting as the server/victim (IP: 10.0.2.15) and VM2 as the attacker/client (IP: 10.0.2.6).

Prerequisites
Hardware: A computer with VirtualBox installed, capable of running two VMs.
Software:
Two Kali Linux VMs (download from kali.org).
Wireshark, Hydra, Fail2Ban, Snort, OpenVPN, and Easy-RSA installed on Kali Linux.
A sample pcap file (turkey-malware-injection.pcap) for Wireshark analysis (download from a trusted source or use a provided link).
Network Setup: Both VMs on a VirtualBox NAT network with IPs 10.0.2.15 (VM1) and 10.0.2.6 (VM2).
Files:
Create userlist.txt (containing testuser) and passlist.txt (containing weak passwords like password123) for the SSH attack.
Ensure root privileges for all commands (sudo).

Lab Setup
Configure VMs:
Install Kali Linux on both VMs.
Set VM1’s IP to 10.0.2.15 and VM2’s to 10.0.2.6 in VirtualBox NAT network settings.
Update Kali: sudo apt update && sudo apt upgrade -y.



Install Required Tools:
On both VMs: sudo apt install wireshark hydra fail2ban snort openvpn easy-rsa -y.
Prepare Files:
On VM2, create userlist.txt and passlist.txt in /home/kali/:
echo "testuser" > userlist.txt
echo "password123" > passlist.txt
Download or obtain turkey-malware-injection.pcap for Wireshark analysis.

Lab Experiments

Experiment 1: SSH Brute-Force Attack and Mitigation

Objective: Simulate an SSH brute-force attack on an IoT device and secure it with Fail2Ban.

Steps
Set Up SSH Server on VM1:
Install OpenSSH: sudo apt install openssh-server -y.
Enable and start SSH: sudo systemctl enable ssh && sudo systemctl start ssh.
Verify SSH status: sudo systemctl status ssh (should show active (running)).
Create a test user: sudo adduser testuser (set password to password123).
Edit SSH config (sudo nano /etc/ssh/sshd_config):

PermitRootLogin yes
MaxAuthTries 3
PasswordAuthentication yes

Restart SSH: sudo systemctl restart ssh.

Simulate Brute-Force Attack from VM2:

Run Hydra: hydra -L userlist.txt -P passlist.txt -t 4 ssh://10.0.2.15.

Expected Outcome: Hydra retrieves testuser:password123 and allows remote login (ssh testuser@10.0.2.15).
Mitigate with Fail2Ban on VM1:
Install Fail2Ban: sudo apt install fail2ban -y && sudo systemctl start fail2ban && sudo systemctl enable fail2ban.
Configure Fail2Ban (sudo nano /etc/fail2ban/jail.local):

[sshd]
enabled = true
port = ssh
maxretry = 3
bantime = 3600
findtime = 600



Restart Fail2Ban: sudo systemctl restart fail2ban.
Re-run the Hydra attack from VM2.

Expected Outcome: After 3 failed attempts, VM2’s IP (10.0.2.6) is banned. Check logs: sudo tail -f /var/log/fail2ban.log.

Capture Evidence:

Screenshot SSH service status, Hydra output, Fail2Ban logs, and banned IP.

Experiment 2: Wireshark Traffic Analysis

Objective: Analyze a pcap file to identify a Man-on-the-Side attack involving malicious HTTP redirects.

Steps

Open Pcap File:


On VM1 or VM2, launch Wireshark: wireshark &.

Load turkey-malware-injection.pcap.
Analyze Traffic:
I/O Graph: Go to Statistics > I/O Graphs to observe packet rate spikes (indicating redirects).
Endpoint Statistics: Go to Statistics > Endpoints to list IPs (e.g., client: 159.65.45.200, server: 85.105.114.98, malicious: 195.175.84.250).
Packet List: Filter for HTTP (http) and inspect Frame 32 (GET request for vlc-2.2.0-8-win32.exe followed by a 307 Temporary Redirect).
HTTP Stream: Right-click Frame 32, select Follow > HTTP Stream to view the redirect to a malicious URL (e.g., http://ad18af0bcab7c849bf236d427121d606f).
Key Observations:
The client is redirected from legitimate software downloads (e.g., VLC, Avast) to malicious EXEs via 307 redirects.



The quick redirect timing (0.15s) suggests a MotS attack.



The malicious URL’s domain and hexadecimal query string indicate spyware (e.g., FinFisher).



Capture Evidence:





Screenshot I/O graph, endpoint statistics, packet list, and HTTP stream.

Experiment 3: Firewall Configuration with iptables

Objective: Configure iptables to block Nmap SYN and Xmas scans.

Steps

Flush Existing Rules on VM1:
Clear rules: sudo iptables -F && sudo iptables -X.
Set default policies: sudo iptables -P FORWARD ACCEPT && sudo iptables -P OUTPUT ACCEPT.

Simulate SYN Scan from VM2:
Run: nmap -sS 10.0.2.15.
Expected Outcome: Nmap identifies open ports (e.g., 22/SSH).
Block SYN Scan on VM1:
Add rule:

sudo iptables -A INPUT -p tcp --syn --dport 22 -m state --state NEW -m recent --rcheck --seconds 60 --hitcount 5 -j REJECT --reject-with tcp-reset
Re-run Nmap scan from VM2.
Expected Outcome: Scan fails after 5 SYN packets in 60 seconds. Check rule hit count: sudo iptables -L -v.


Simulate Xmas Scan from VM2:
Run: nmap -sX 10.0.2.15.
Expected Outcome: Nmap detects ports as filtered.

Block Xmas Scan on VM1:

Add rule:

sudo iptables -A INPUT -p tcp --tcp-flags ALL FIN,URG,PSH -j REJECT --reject-with tcp-reset
Re-run Xmas scan from VM2.
Expected Outcome: Scan fails. Capture Wireshark pcap showing TCP resets.



Capture Evidence:

Screenshot Nmap outputs, iptables rule counts, and Wireshark pcaps.


Experiment 4: Intrusion Detection with Snort

Objective: Configure Snort to detect ICMP and SSH traffic.

Steps
Install Snort on VM1:
Install: sudo apt install snort -y.
Configure home network: Set HOME_NET to 10.0.2.0/24 in /etc/snort/snort.conf.
Run Snort in Packet Logger Mode:

Command: sudo snort -A console -c /etc/snort/snort.conf -i eth0 -l /var/log/snort.

Generate HTTPS traffic from VM2: Open https://www.bradford.ac.uk in a browser.
Verify logs: sudo snort -r /var/log/snort/snort.log.* -b "tcp port 443".
Expected Outcome: Logs show TCP handshake for port 443.



Create ICMP Rule:
Edit /etc/snort/rules/local.rules:
alert icmp any any -> any any (msg:"ICMP Traffic Detected"; sid:10000001; classtype:network-scan;)
Run Snort: sudo snort -A console -c /etc/snort/snort.conf -i eth0.
Ping VM1 from VM2: ping 10.0.2.15.



Expected Outcome: Snort alerts on ICMP traffic.


Create SSH Rule:

Add to /etc/snort/rules/local.rules:

alert tcp any any -> any 22 (msg:"SSH Traffic Detected"; sid:10000002; classtype:attempted-admin;)

Run Snort and attempt SSH login from VM2: ssh testuser@10.0.2.15.

Expected Outcome: Snort alerts on SSH traffic.


Capture Evidence:

Screenshot Snort alerts, log files, and rule configurations.


Experiment 5: VPN Setup with OpenVPN

Objective: Establish a TLS-based VPN between VM1 (server) and VM2 (client).

Steps

Install OpenVPN and Easy-RSA on Both VMs:
Command: sudo apt install openvpn easy-rsa -y.
Generate Keys and Certificates on VM1:

Initialize Easy-RSA:

mkdir ~/easy-rsa && ln -s /usr/share/easy-rsa/* ~/easy-rsa/ && cd ~/easy-rsa
./easyrsa init-pki

Create CA: ./easyrsa build-ca nopass (Common Name: VPN-CA).

Generate server certs: ./easyrsa gen-req server nopass && ./easyrsa sign-req server server.
Generate client certs: ./easyrsa gen-req client1 nopass && ./easyrsa sign-req client client1.
Generate Diffie-Hellman: ./easyrsa gen-dh.
Copy files: sudo cp pki/ca.crt pki/issued/server.crt pki/private/server.key pki/dh.pem /etc/openvpn/.
Configure and Start Server on VM1:



Create /etc/openvpn/server.conf:

port 1194
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
server 10.8.0.0 255.255.255.0
push "redirect-gateway def1"
keepalive 10 120
cipher AES-256-CBC
persist-key
persist-tun



Start server: sudo openvpn --config /etc/openvpn/server.conf &.
Transfer Files to VM2:

From VM1: sudo scp /etc/openvpn/ca.crt ~/easy-rsa/pki/issued/client1.crt ~/easy-rsa/pki/private/client1.key kali@10.0.2.6:/home/kali/.
Configure and Start Client on VM2:
Move files: sudo mkdir -p /etc/openvpn && sudo mv /home/kali/{ca.crt,client1.crt,client1.key} /etc/openvpn/.
Create /etc/openvpn/client.conf:

client
dev tun
proto udp
remote 10.0.2.15 1194
resolv-retry infinite
nobind
persist-key
persist-tun
ca ca.crt
cert client1.crt
key client1.key
cipher AES-256-CBC
Start client: sudo openvpn --config /etc/openvpn/client.conf &.


Verify VPN:
On VM2, ping VM1’s VPN IP: ping 10.8.0.1.

Check routing: route (should show tun0 interface).
Capture traffic with Wireshark to confirm encrypted UDP 1194 traffic.
Capture Evidence:

Screenshot VPN connection, routing table, and Wireshark capture.

Expected Outcomes





SSH Attack: Hydra successfully retrieves credentials before mitigation; Fail2Ban blocks the attack after configuration.



Wireshark: Pcap analysis reveals malicious 307 redirects and MotS attack patterns.



Firewall: iptables rules block SYN and Xmas scans, confirmed by failed Nmap attempts.



Snort: Alerts triggered for ICMP and SSH traffic, logged appropriately.



VPN: Secure tunnel established, with encrypted traffic between VMs.





A brief report summarizing findings and mitigation effectiveness.

