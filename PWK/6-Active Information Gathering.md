# 6-Active Information Gathering

## DNS 枚举

### 与DNS交互

每个域可以使用不同类型的DNS记录。一些最常见的DNS记录类型包括:

NS -域名服务器记录包含托管某个域的DNS记录的权威服务器的名称。

A -也称为主机记录，“A记录”包含主机名的IP地址(如www.baidu.com)。

MX -邮件交换记录包含负责处理域名电子邮件的服务器名称。一个域可以包含多个MX记录。

PTR -指针记录用于反向查找区域，用于查找与IP地址相关的记录。

CNAME - 标准名称记录用于为其他主机记录创建别名。

TXT -文本记录可以包含任意数据，可以用于各种目的，如域所有权验证。

例如：

```
host www.baidu.com
```

-t 选项指定我们要查找的记录的类型

```
host -t mx www.baidu.com
host -t txt www.baidu.com
```

### 自动查找

通过使用 `host` 命令查找指定域名的IP地址，根据返回的信息不同，可以判断是否存在此域名。

```
host www.baidu.com
host xiajibaqiaode.baidu.com
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1604909723871-18f0884c-33a9-4deb-84c4-a14e39358f48.png)

会有这种情况发生，就是明明不存在的，但是也会返回一个地址，通常是固定的，这种情况一般是因为使用了公共的DNS。

### 蛮力正向查找

通过构建子域名名字，然后每行一个，放在一个文件里，然后用host去遍历，也可以自己用grep根据规律将有地址的提取出来。

```
for sub in $(cat list.txt); do host $sub.baidu.com; done
```

通过 `sudo apt install seclists` 可以下载一些可以直接用的列表文件，默认放在/usr/share/seclists。

### 蛮力反相查找

反相查找是需要查找对象支持的。

```
for ip in $(seq 50 100); do host 38.100.193.$ip; done | grep -v "not found"
```

### DNS区域传输

区域传输基本上是相关DNS服务器之间的数据库复制，其中区域文件从主DNS服务器复制到从服务器。区域文件包含为该区域配置的所有DNS名称的列表。区域传输应该只允许授权的从DNS服务器，但许多管理员错误配置了他们的DNS服务器，在这些情况下，任何要求DNS服务器区域副本的人通常都会收到一个副本。

host -l <domain name> <dns server address>

```
host -l megacorpone.com ns1.megacorpone.com
```

这个因为需要DNS服务器的配置，现在的DNS服务器大都是像阿里云这种，所以要是想测试处结果，可能需要自己配置环境。

获取域名服务器： `host -t ns baidu.com | cut -d " " -f 4` 

简单的脚本（根据给定的域名，查询域名服务器，然后再遍历区域传输）：

```
#!/bin/bash
#判断是否有参数输入，没有就退出
if [ -z "$1" ]
then 
    echo "[*] Simple Zone transfer script" 
  echo "[*] Usage : $0 <domain name> " 
  exit 0 
fi

for server in $(host -t ns $1 | cut -d " " -f4)
do
    host -l $1 $server |grep "has address" 
done
```

### kali中的相关工具

#### DNSRecon

DNSRecon 是用Python编写的高级、现代DNS枚举脚本。使用-d选项指定域名，-D指定包含可能的子域字符串的文件名，使用-t选项指定要执行的枚举类型。axfr是区域传输，brt是蛮力。

```
dnsrecon -d baidu.com -t axfr
dnsrecon -d baidu.com -D ~/list.txt -t brt
```

#### DNSenum

```
dnsenum zonetransfer.me
```

## 端口扫描

### TCP/UDP 扫描

> 这里先用的nc扫描的，可以自己用wireshark之类的查看数据包观察一下

#### TCP扫描

最简单的TCP扫描通常被称为连接扫描，依赖于TCP的三次握手机制。

在端口3388-3390上运行TCP Netcat端口扫描。-w选项指定连接超时，以秒为单位，-z用于指定零I/O模式，该模式将不发送数据，用于扫描:

```
nc -nv -w 1 -z 10.211.55.5 3388-3390
```

#### UDP扫描

nc在连接时用-u指定UDP

```
nc -nv -u -z -w 1 10.211.55.5 160-162
```

#### 常见端口扫描缺陷

因为UDP的不可靠性，所以一般人们比较关注于感兴趣的TCP端口，但是这也导致UDP端口经常被服务器管理者忽略，虽然UDP扫描可能是不可靠的，但是也是有可能存在漏洞的。

### Nmap 端口扫描

Nmap的操作可以去Tools->Nmap阅读，这里就不多写了。[点击阅读](https://www.yuque.com/soft98/websec/zkm4hp)

这里说一下 Nmap Scripting Engine (NSE)

连接目标主机的SMB： `nmap 10.211.55.5 --script=smb-os-discovery` 

DNS区域传输： `nmap --script=dns-zone-transfer -p53 ns2.megacorpone.com` 

查看脚本的信息： `nmap --script-help dns-zone-transfer` 

### Masscan

Masscan 可以说是最快的端口扫描器;它可以在大约6分钟内扫描整个互联网，每秒传输惊人的1000万个数据包!虽然它最初设计扫描整个互联网，它可以轻松处理a类或B子网。

安装： `sudo apt install masscan` 

-rate 指定数据包传输的期望速率，-e 指定要使用的原始网络接口，-router-ip 指定适当网关的IP地址:

```
sudo masscan -p80 10.211.55.0/24 --rate=1000 -e eth0 --router-ip 10.211.55.1
```

## Server Message Block (SMB)  枚举

### 扫描NetBIOS服务

NetBIOS 服务监听TCP端口139和几个UDP端口。需要注意的是，SMB (TCP端口445)和NetBIOS是两个独立的协议。NetBIOS是一个独立的会话层协议和服务，它允许本地网络上的计算机彼此通信。虽然SMB的现代实现可以在没有NetBIOS的情况下工作，但是TCP (NBT) 上的NetBIOS需要向后兼容，并且通常是同时启用的。因此，这两个服务的枚举通常是同时进行的。这些可以通过像nmap这样的工具进行扫描，使用类似于下面的语法:

```
nmap -v -p 139,445 -oG smb.txt 10.211.55.1-254
```

还有其他更专门的工具用于特定地标识NetBIOS信息，如以下示例中使用的 nbtscan。-r选项用于指定原始UDP端口为137，用于查询NetBIOS名称服务的有效NetBIOS名称:

```
sudo nbtscan -r 10.211.55.0/24
```

### Nmap SMB NSE 脚本

脚本一般存放在 `/usr/share/nmap/scripts` 

```
nmap 10.211.55.5 --script=smb-os-discovery
```

要检查已知的SMB协议漏洞，我们可以调用其中一个SMB -vuln NSE脚本。我们将研究一下smb-vuln-ms08-067，它使用--script-args选项将参数传递给NSE脚本。如果我们设置脚本参数unsafe=1，将运行的脚本为几乎(或完全)保证会使脆弱的系统崩溃。所以要慎用。

```
nmap -v -p 139,445 --script=smb-vuln-ms08-067 --script-args=unsafe=1 10.211.55.5
```

## NFS 枚举

网络文件系统(NFS) 是一种分布式文件系统协议，最初由Sun Microsystems在1984年开发。它允许客户端计算机上的用户通过计算机网络访问文件，就好像它们是在本地安装的存储上一样。NFS经常与UNIX操作系统一起使用，它的主要实现是不安全的。安全设置可能有些困难，因此发现NFS共享对全世界开放的情况并不少见。这对于作为渗透测试人员的我们来说非常方便，因为我们可以利用他们来收集敏感信息，提高我们的特权，等等。

### 扫描NFS共享

Portmapper 和RPCbind 都在TCP端口111上运行。RPCbind将RPC服务映射到它们侦听的端口。RPC进程在启动时通知rpcbind，并注册它们正在监听的端口和它们期望提供服务的RPC程序编号。

```
nmap -v -p 111 10.211.55.1-254
nmap -sV -p 111 --script=rpcinfo 10.211.55.1-254
```

### Nmap NFS NSE 脚本

```
nmap -p 111 --script nfs* 10.211.55.5
```

假设10.211.55.5的/home开放了共享，然后我们将其挂载到本地

```
mkdir home
```

我们将使用mount和-o nolock来禁用文件锁定，这是旧的NFS服务器经常需要的:

```
sudo mount -o nolock 10.211.55.5:/home ~/home/
```

## SMTP 枚举

我们还可以从易受攻击的邮件服务器收集有关主机或网络的信息。简单邮件传输协议(SMTP) 支持几个有趣的命令，比如VRFY和EXPN。VRFY请求请求服务器验证电子邮件地址，而EXPN请求服务器确认邮件列表的成员。这些信息经常被用来验证邮件服务器上的现有用户，这在渗透测试中是非常有用的信息。

```
nc -nv 10.211.55.5 25
```

如果开放了，是可以通过交互输入 `VRFY 用户名` 来验证用户是否存在。

Python脚本：

```
#!/usr/bin/python
import socket 
import sys

if len(sys.argv) != 2:
    print "Usage: vrfy.py <username>"
    sys.exit(0)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connect = s.connect(('10.211.55.5',25))
banner = s.recv(1024)
print banner
s.send('VRFY ' + sys.argv[1] + '\r\n')
result = s.recv(1024)
print result
s.close()
```

## SNMP 枚举

SNMP基于UDP, UDP是一种简单的无状态协议，因此容易受到IP欺骗和重放攻击。此外，常用的SNMP协议1、2和2c不提供流量加密，这意味着可以在本地网络上轻松截获SNMP信息和凭证。传统的SNMP协议也有较弱的身份验证方案，通常使用默认的公共和私有社区字符串进行配置。

### SNMP MIB树

SNMP管理信息库(MIB)是一个数据库，通常包含与网络管理相关的信息。数据库像树一样组织起来，其中的分支表示不同的组织或网络功能。树的叶子(最终端点)对应于特定的变量值，外部用户可以访问和探测这些变量值。IBM Knowledge Center 包含大量关于MIB树的信息。

Windows SNMP MIB values：

| 1.3.6.1.2.1.25.1.6.0   | System Processes |
| ---------------------- | ---------------- |
| 1.3.6.1.2.1.25.4.2.1.2 | Running Programs |
| 1.3.6.1.2.1.25.4.2.1.4 | Processes Path   |
| 1.3.6.1.2.1.25.2.3.1.4 | Storage Units    |
| 1.3.6.1.2.1.25.6.3.1.2 | Software Name    |
| 1.3.6.1.4.1.77.1.2.25  | User Accounts    |
| 1.3.6.1.2.1.6.13.1.3   | TCP Local Ports  |

### 扫描SNMP

```
sudo nmap -sU --open -p 161 10.211.55.1-254 -oG open-snmp.txt
```

可以使用诸如onesixtyone这样的工具，它将尝试对IP地址列表进行强力攻击。首先，我们必须建立文本文件包含社区字符串和IP地址:

```
echo public > community
echo private >> community
echo manager >> community
for ip in $(seq 1 254); do echo 10.211.55.$ip; done > ips
onesixtyone -c community -i ips
```

### Windows SNMP 枚举实例

只要我们至少知道SNMP只读社区字符串(在大多数情况下是“公共的”)，我们就可以使用snmpwalk等工具探测和查询SNMP值。

#### 枚举整个MIB树

-c选项指定社区字符串，-v选项指定SNMP版本号，-t 10选项将超时时间增加到10秒:

```
snmpwalk -c public -v1 -t 10 10.211.55.5
```

#### 枚举Windows用户

```
snmpwalk -c public -v1 10.211.55.5 1.3.6.1.4.1.77.1.2.25
```

#### 枚举正在运行的Windows进程

```
snmpwalk -c public -v1 10.211.55.5 1.3.6.1.2.1.25.4.2.1.2
```

#### 枚举打开的TCP端口

```
snmpwalk -c public -v1 10.211.55.5 1.3.6.1.2.1.6.13.1.3
```

#### 枚举安装的软件

```
snmpwalk -c public -v1 10.211.55.5 1.3.6.1.2.1.25.6.3.1.2
```