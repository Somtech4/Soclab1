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

<img width="468" alt="image" src="https://github.com/user-attachments/assets/bdddd14b-5e4d-437c-b1d9-a2fbfc101e25" />

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

<img width="468" alt="image" src="https://github.com/user-attachments/assets/4ae44193-0a3a-4843-95f0-53d5fa5170c5" />




Experiment 3: Firewall Configuration with iptables

Objective: Configure iptables to block Nmap SYN and Xmas scans.

Steps

Flush Existing Rules on VM1:
Clear rules: sudo iptables -F && sudo iptables -X.
Set default policies: sudo iptables -P FORWARD ACCEPT && sudo iptables -P OUTPUT ACCEPT.

Simulate SYN Scan from VM2:
Run: nmap -sS 10.0.2.15.

Block SYN Scan on VM1:
Add rule:

sudo iptables -A INPUT -p tcp --syn --dport 22 -m state --state NEW -m recent --rcheck --seconds 60 --hitcount 5 -j REJECT --reject-with tcp-reset
Re-run Nmap scan from VM2.



Simulate Xmas Scan from VM2:
Run: nmap -sX 10.0.2.15.

<img width="468" alt="image" src="https://github.com/user-attachments/assets/177ca5d4-b9db-43e4-9e95-8e9231cec6c0" />


Block Xmas Scan on VM1:

Add rule:

sudo iptables -A INPUT -p tcp --tcp-flags ALL FIN,URG,PSH -j REJECT --reject-with tcp-reset
Re-run Xmas scan from VM2.
<img width="468" alt="image" src="https://github.com/user-attachments/assets/01ca3316-0619-4228-b992-f7b4ae33d94b" />.





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
<img width="468" alt="image" src="https://github.com/user-attachments/assets/9544afd8-e416-4f13-ba19-a443073b31fc" />




Create ICMP Rule:
Edit /etc/snort/rules/local.rules:
alert icmp any any -> any any (msg:"ICMP Traffic Detected"; sid:10000001; classtype:network-scan;)
<img width="468" alt="image" src="https://github.com/user-attachments/assets/c2393a04-5ae9-430a-a559-df733531df7e" />

Run Snort: sudo snort -A console -c /etc/snort/snort.conf -i eth0.
Ping VM1 from VM2: ping 10.0.2.15.



<img width="468" alt="image" src="https://github.com/user-attachments/assets/6eec5a88-274d-4eae-97de-86b36ecacdc5" />



Create SSH Rule:

Add to /etc/snort/rules/local.rules:

alert tcp any any -> any 22 (msg:"SSH Traffic Detected"; sid:10000002; classtype:attempted-admin;)
<img width="468" alt="image" src="https://github.com/user-attachments/assets/82c7f0c6-a5a2-40fe-95f0-d1f900223992" />


Run Snort and attempt SSH login from VM2: ssh testuser@10.0.2.15.

<img width="468" alt="image" src="https://github.com/user-attachments/assets/e1ca837f-6126-47b0-b0ea-1819ac05f64b" />





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
<img width="468" alt="image" src="https://github.com/user-attachments/assets/0bae119d-d1d0-4ce6-ba75-99caa39ac071" />

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
<img width="468" alt="image" src="https://github.com/user-attachments/assets/630f384c-f64f-403f-bdfb-5b886f362968" />
<img width="468" alt="image" src="https://github.com/user-attachments/assets/683e331d-733f-4a6b-8aff-3a67e0f25fae" />
<img width="468" alt="image" src="https://github.com/user-attachments/assets/85b417a7-fca2-4ea5-9837-2092cf0e22e3" />
<img width="468" alt="image" src="https://github.com/user-attachments/assets/426d489f-21ff-4ab9-a755-0d15c56fff39" />



A brief report summarizing findings and mitigation effectiveness.

