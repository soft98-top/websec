# Nmap

> Nmap参考指南：https://github.com/shmilylty/Nmap-Reference-Guide

这篇文章只是对Nmap的指令的一个简单的摘抄，部分指令并没有写出来，详细内容可以去上面的链接阅读以下，原文篇幅不长，相信读完你对Nmap的用法就相当清晰了。

## 主机发现

-sL：列表扫描，只是简单列出扫描的所有地址。

-sP：Ping扫描，只进行主机发现，将在线的主机打印出来。

-P0/-Pn：跳过发现阶段，不进行Ping操作。主要用于已确定存活的主机，进行其它扫描操作。前面的在新版已经被舍弃，建议使用后面的。

-PS [portlist]：TCP SYN Ping，指令后面跟随0个或多个端口，默认为80端口。

-PA [portlist]：TCP ACK Ping，指令后面跟随0个或多个端口，默认为80端口。

-PU [potlist]：UDP Ping，指令后面跟随0个或多个端口，默认为31338端口。

-PE; -PP; -PM：ICMP Ping Types，-PE是回声请求、-PP是时间戳、-PM是地址掩码。

-PR：ARP Ping，用于在以太局域网内使用，如果Nmap发现目标主机是局域网下的，默认使用ARP PIng，如果不想用ARP扫描，可以设置 --send-ip。

-n：不用域名解析。

-R：为所有目标解析域名。

--system-dns：使用系统域名解析。

## 端口扫描

-sS：TCP SYN扫描。

-sT：TCP connect()扫描，通过创建connect()系统调用进行链接。

-sU：UDP扫描。

-sN：TCP Null扫描。

-sF：TCP FIN扫描。

-sX：Xmas扫描，即FIN、PSH、URG标志位扫描。

-sA：TCP ACK扫描。

-sW：TCP窗口扫描。

-sM：TCP Maimon扫描，针对基于BSD的系统。

--scanflags：定制化扫描，后面跟随TCP的标志位字符串，只要是URG， ACK，PSH， RST，SYN，and FIN的任何组合就行。例如，—scanflags URGACKPSHRSTSYNFIN设置了所有标志位。

-sI：Idlescan，说的很高级，具体没尝试。https://nmap.org/book/idlescan.html。

-sO：IP协议扫描，用于确定目标主机支持哪些协议。

-b：FTP弹跳扫描。



-p：后面跟随指定的端口，可以是多个，例如 80 或者 80,22,8888 或者 1-1023。用于扫描指定端口。

-F：快速扫描，nmap内置的有限端口扫描。

-r：按顺序扫描，Nmap默认使用随机顺序扫描。

## 服务和版本探测

-sV：版本探测。

--allports：不为版本探测排除任何端口。

--version-intensity：设置版本扫描强度，后面跟随数字0 ~ 9。

--version-light：轻量级模式 == --version-intensity 2。

--version-all：尝试每个探测 == --version-intensity 9。

--version-trace：跟踪版本扫描活动。

-sR：RPC扫描。

## 操作系统探测

-O：探测操作系统。

--osscan-limit：针对指定的目标进行操作系统检测。

--osscan-guess;--fuzzy：推测操作系统结果。

## 时间

-T：设置时间模板，后面跟随0-5或者模板名称，模板名称有paranoid (0)、sneaky (1)、polite (2)、normal(3)、 aggressive (4)和insane (5)，数字越高速度越快，准确性越低，跟当下的网络环境有关系。

## 防火墙/IDS躲避和欺骗

-f：报文分段。

--mtu：使用指定的MTU。

-D：使用诱饵隐蔽扫描，后面跟随诱饵主机IP地址，诱饵主机之间用逗号隔开，详细使用请自行搜索和查看原文。

-S：源地址欺骗，结合-e或者-P0使用。

-e：使用指定的接口。

--source-port;-g：源端口欺骗，后面跟随端口号。

--data-length：发送报文时附加随机数据，对标准的报文进行补全，会影响大部分ping和端口扫描的速度。

--ttl：设置IP time-to-live域。

--randomize-hosts：对目标主机的顺序进行随机化。

--spoof-mac：MAC地址欺骗。

## 输出

-oN：标准输出，后面跟上文件名。

-oX：以XML形式输出，后面跟上文件名。

-oS：脚本小子输出。

-oG：Grep输出，简化输出，便于工具查找和分解，后面跟随文件名。

-oA：以所有形式输出，输出多份文件，可跟随文件目录名。

-v：详细输出。

-d：提高或设置调试级别，后面可跟随0-9设置调试级别，不带参数则是提高一个等级。

--apend-output：在输出文件中添加，不加这个选项默认输出完全覆盖文件。

--resume：继续中断的扫描。

## 其它

-6：IPV6扫描。

-A：激烈模式扫描，代表性就是开了-O和-sV。

--datadir：说明用户Nmap数据的存放位置，用于指定一些配置文件。

--send-eth：使用原以太网帧发送，适合于windos。

--send-ip：在原IP层发送。

-V;--version：打印Nmap版本信息。

-h;--help：打印帮助信息。

## 原文实例

```shell
nmap -v scanme.nmap.org

这个选项扫描主机scanme.nmap.org中 所有的保留TCP端口。选项-v启用细节模式。

nmap -sS -O scanme.nmap.org/24

进行秘密SYN扫描，对象为主机Saznme所在的“C类”网段 的255台主机。同时尝试确定每台工作主机的操作系统类型。因为进行SYN扫描 和操作系统检测，这个扫描需要有根权限。

nmap -sV -p 22，53，110，143，4564 198.116.0-255.1-127

进行主机列举和TCP扫描，对象为B类188.116网段中255个8位子网。这 个测试用于确定系统是否运行了sshd、DNS、imapd或4564端口。如果这些端口 打开，将使用版本检测来确定哪种应用在运行。

nmap -v -iR 100000 -P0 -p 80

随机选择100000台主机扫描是否运行Web服务器(80端口)。由起始阶段 发送探测报文来确定主机是否工作非常浪费时间，而且只需探测主机的一个端口，因 此使用-P0禁止对主机列表。

nmap -P0 -p80 -oX logs/pb-port80scan.xml -oG logs/pb-port80scan.gnmap 216.163.128.20/20

扫描4096个IP地址，查找Web服务器(不ping)，将结果以Grep和XML格式保存。

host -l company.com | cut -d -f 4 | nmap -v -iL

进行DNS区域传输，以发现company.com中的主机，然后将IP地址提供给 Nmap。上述命令用于GNU/Linux — 其它系统进行区域传输时有不同的命令。
```