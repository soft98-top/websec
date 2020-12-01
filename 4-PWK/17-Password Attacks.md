# 17-Password Attacks

密码是用户帐户和服务身份验证的最基本形式，通过扩展，密码攻击的目标是发现和使用有效凭据，以便获得对用户帐户或服务的访问权限。

一般来说，有几种常见的密码攻击方法。我们可以尝试通过使用各种单词表的字典攻击来猜测密码，也可以使用暴力破解密码中的每个可能的字符。

## Worldlists

单词表，有时也被称为字典文件，是一个简单的文本文件，它包含一些单词，可以作为测试密码的程序的输入。在考虑字典攻击时，精确性通常比覆盖率更重要，这意味着创建一个包含相关密码的精简单词表比创建一个庞大的通用单词表更重要。正因为如此，许多单词表都基于一个共同的主题，例如流行文化参考、特定行业或地理区域，并经过改进以包含常用密码。Kali Linux在/usr/share/wordlist/目录中包含了许多这样的字典文件，还有更多的是在线托管的。

### Standard Wordlists

我们可以通过添加特定于目标组织的单词和短语来提高单词列表的有效性。

CeWL（自定义单词列表生成器）是一个ruby应用程序，它将给定的URL搜索到指定的深度，并返回一个单词列表。

例如，下面的命令将www.megacorpone.com网站，查找最少包含六个字符的单词（-m 6），并将单词列表（-w）写入自定义文件（megacorpcewl.txt):

```
cewl www.megacorpone.com -m 6 -w megacorpcewl.txt
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606801633868-30be7124-0c0b-4894-97e2-b63874f43026.png)

john - 一个工具，找到你的用户弱密码，可以通过设置规则，对之前产生的数据做处理，假设密码的格式是英文单词然后紧跟两位数字，然后我们修改一下规则文件。软件的规则语法很丰富，可以自行研究。

```
sudo nano /etc/john/john.conf
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606802105916-4ea6afa0-fba8-4b16-82b4-01bb1f533449.png)

为此，我们将调用john并指定字典文件（--wordlist=megacorpcewl.txt)，激活配置文件（--rules）中的规则，将结果输出到标准输出（--stdout），并将该输出重定向到名为mutated.txt:

```
john --wordlist=megacorpcewl.txt --rules --stdout > mutated.txt
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606802413019-b66504a0-7881-46bc-950b-a5072aca40bc.png)

## Brute Force Wordlists

与字典攻击不同，暴力密码攻击计算并测试可能构成密码的每个可能的字符组合，直到找到正确的密码为止。虽然这听起来像是保证结果的简单方法，但它非常耗时。根据密码的长度和复杂程度以及测试系统的计算能力，暴力破解一个强密码可能需要很长时间，甚至几年。

假如我们的密码格式十分固定，就像下面这种，一个大写字母，两个小写字母，两个特殊符号，三个数字：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606803092273-6bedd615-b328-41fc-b21b-b6b9b19ca797.png)

有了这些知识，创建一个包含与此模式匹配的所有可能密码的单词表将非常有用。包含在kali linux中的Crunch是一个强大的单词表生成器，可以处理这个任务。

首先，我们必须描述需要crunch复制的模式，为此，我们将使用表示特定类型字符的占位符：

```
@ -> 小写字母` `, -> 大写字母` `% -> 数字` `^ -> 特殊字符（包括空格）
```

为了生成符合我们要求的单词表，我们将指定最小和最大单词长度为8个字符（8 8），并用-t ,@@^^%%%来描述我们的规则模式：

```
crunch 8 8 -t ,@@^^%%%
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606803431057-aaefc53f-986d-4ecd-b4d1-e6ec23633c92.png)

我们也可以用crunch定义一个字符集。例如，我们可以创建一个暴力字表，说明密码长度在4到6个字符之间（4 6），只包含字符0-9和a-F（0123456789ABCDEF），然后我们将输出写入一个文件（-o crunch.txt):

```
crunch 4 6 0123456789ABCDEF -o crunch.txt
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606803545475-641a9594-8459-4227-be7d-80de75a6d13a.png)

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606803637699-893e75fa-c228-4009-a1d0-3e09f5f51bfe.png)

此外，我们可以根据预定义的字符集生成密码，比如在/usr/share/crunch/charset.lst中定义的字符集. 例如，我们可以指定字符集文件的路径（-f /usr/share/crunch/charset.lst)然后选择混合字母集mixalpha，它包括所有小写字母和大写字母：

```
crunch 4 6 -f /usr/share/crunch/charset.lst mixalpha -o crunch.txt
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606803811578-ea49d53c-6658-421b-9d95-854c3fb6cd73.png?x-oss-process=image%2Fresize%2Cw_1500)

## 常见的网络服务攻击方法

请记住，针对网络服务的密码攻击是嘈杂的，在某些情况下是危险的。多次失败的登录尝试通常会在目标系统上生成日志和警告，甚至可能在预先定义的登录失败次数后锁定帐户。在渗透测试期间，这可能是灾难性的，在管理员重新启用帐户之前，用户无法访问生产系统。在盲目运行基于网络的暴力攻击之前，请记住这一点。

网络服务密码攻击背后隐藏的艺术是在发起攻击之前，谨慎而智能地选择适当的目标、用户列表和密码文件。

### HTTP htaccess Attack with Medusa

据其作者所说，美杜莎的目标是成为一个“快速、大规模并行、模块化、登录暴力强制器”。

我们将使用Medusa来尝试访问受htaccess保护的web目录。

首先，我们将设置我们的目标，一个安装在Windows客户机上的Apache web服务器，我们将通过XAMPP控制面板启动它。我们将尝试访问该服务器上受htaccess保护的文件夹/admin。本例中我们选择的单词表是/usr/share/wordlist/rockyou.txt.gz，我们必须先用gunzip解压：

```
sudo gunzip /usr/share/wordlists/rockyou.txt.gz
```

接下来，我们将启动medusa，使用-h 10.11.0.22对目标主机上htaccess保护的URL（-m DIR:/admin）的攻击。

我们将使用rockyou wordlist文件（-P/usr/share/wordlist/rockyou.txt）中的密码攻击管理员用户（-u admin）当然，还会使用HTTP身份验证方案（-M）：

```
medusa -h 10.11.0.22 -u admin -P /usr/share/wordlists/rockyou.txt -M http -m DIR:/admin
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606807014593-c9883b3d-e574-4d63-bcc2-d44befccfa91.png?x-oss-process=image%2Fresize%2Cw_1500)

在这种情况下，美杜莎发现了一个工作密码“freedom”。

不带参数输入medusa运行，会出现帮助菜单：

```
Medusa v2.2 [http://www.foofus.net] (C) JoMo-Kun / Foofus Networks <jmk@foofus.net>

ALERT: Host information must be supplied.

Syntax: Medusa [-h host|-H file] [-u username|-U file] [-p password|-P file] [-C file] -M module [OPT]
  -h [TEXT]    : Target hostname or IP address
  -H [FILE]    : File containing target hostnames or IP addresses
  -u [TEXT]    : Username to test
  -U [FILE]    : File containing usernames to test
  -p [TEXT]    : Password to test
  -P [FILE]    : File containing passwords to test
  -C [FILE]    : File containing combo entries. See README for more information.
  -O [FILE]    : File to append log information to
  -e [n/s/ns]  : Additional password checks ([n] No Password, [s] Password = Username)
  -M [TEXT]    : Name of the module to execute (without the .mod extension)
  -m [TEXT]    : Parameter to pass to the module. This can be passed multiple times with a
                 different parameter each time and they will all be sent to the module (i.e.
                 -m Param1 -m Param2, etc.)
  -d           : Dump all known modules
  -n [NUM]     : Use for non-default TCP port number
  -s           : Enable SSL
  -g [NUM]     : Give up after trying to connect for NUM seconds (default 3)
  -r [NUM]     : Sleep NUM seconds between retry attempts (default 3)
  -R [NUM]     : Attempt NUM retries before giving up. The total number of attempts will be NUM + 1.
  -c [NUM]     : Time to wait in usec to verify socket is available (default 500 usec).
  -t [NUM]     : Total number of logins to be tested concurrently
  -T [NUM]     : Total number of hosts to be tested concurrently
  -L           : Parallelize logins using one username per thread. The default is to process 
                 the entire username before proceeding.
  -f           : Stop scanning host after first valid username/password found.
  -F           : Stop audit after first valid username/password found on any host.
  -b           : Suppress startup banner
  -q           : Display module's usage information
  -v [NUM]     : Verbose level [0 - 6 (more)]
  -w [NUM]     : Error debug level [0 - 10 (more)]
  -V           : Display version
  -Z [TEXT]    : Resume scan based on map of previous scan
```

这个工具可以与各种网络协议交互，这些协议可以用-d选项显示，如下面所示。

```
Medusa v2.2 [http://www.foofus.net] (C) JoMo-Kun / Foofus Networks <jmk@foofus.net>

  Available modules in "." :

  Available modules in "/usr/lib/x86_64-linux-gnu/medusa/modules" :
    + cvs.mod : Brute force module for CVS sessions : version 2.0
    + ftp.mod : Brute force module for FTP/FTPS sessions : version 2.1
    + http.mod : Brute force module for HTTP : version 2.1
    + imap.mod : Brute force module for IMAP sessions : version 2.0
    + mssql.mod : Brute force module for M$-SQL sessions : version 2.0
    + mysql.mod : Brute force module for MySQL sessions : version 2.0
    + nntp.mod : Brute force module for NNTP sessions : version 2.0
    + pcanywhere.mod : Brute force module for PcAnywhere sessions : version 2.0
    + pop3.mod : Brute force module for POP3 sessions : version 2.0
    + postgres.mod : Brute force module for PostgreSQL sessions : version 2.0
    + rexec.mod : Brute force module for REXEC sessions : version 2.0
    + rlogin.mod : Brute force module for RLOGIN sessions : version 2.0
    + rsh.mod : Brute force module for RSH sessions : version 2.0
    + smbnt.mod : Brute force module for SMB (LM/NTLM/LMv2/NTLMv2) sessions : version 2.1
    + smtp-vrfy.mod : Brute force module for verifying SMTP accounts (VRFY/EXPN/RCPT TO) : version 2.1
    + smtp.mod : Brute force module for SMTP Authentication with TLS : version 2.0
    + snmp.mod : Brute force module for SNMP Community Strings : version 2.1
    + ssh.mod : Brute force module for SSH v2 sessions : version 2.1
    + svn.mod : Brute force module for Subversion sessions : version 2.1
    + telnet.mod : Brute force module for telnet sessions : version 2.0
    + vmauthd.mod : Brute force module for the VMware Authentication Daemon : version 2.0
    + vnc.mod : Brute force module for VNC sessions : version 2.1
    + web-form.mod : Brute force module for web forms : version 2.1
    + wrapper.mod : Generic Wrapper Module : version 2.0
```

### Remote Desktop Protocol Attack with Crowbar

Crowbar，正式名为Levye，是一种网络身份验证破解工具，主要用于利用SSH密钥而不是密码。它也是为数不多的能够在现代版本的Windows上对Windows远程桌面协议（RDP）服务进行密码攻击的工具之一。让我们在Windows客户机上试试这个工具。

安装： `sudo apt install crowbar` 

要调用crowbar，我们将指定协议（-b）、目标服务器（-s）、用户名（-u）、单词列表（-C）和线程数（-n），如下所示：

```
crowbar -b rdp -s 10.211.55.8/32 -u soft98 -C ~/password-file.txt -n 1
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606819299339-628343f1-0221-4ee8-a916-6bd53e29ecd7.png?x-oss-process=image%2Fresize%2Cw_1500)

可以通过 `crowbar --help` 查看更多的选项：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606819385603-b2dbf4f3-651e-4b11-b86f-9237f1a34287.png?x-oss-process=image%2Fresize%2Cw_1500)

### SSH Attack with THC-Hydra

THC-Hydra是目前正在积极开发的另一种强大的网络服务攻击工具，值得我们掌握。我们可以利用它来攻击各种协议认证方案，包括SSH和HTTP。

标准选项包括-l指定目标用户名，-P指定单词列表，以及protocol://IP到分别指定目标协议和IP地址。

在第一个示例中，我们将攻击我们的Kali VM。我们将在本地计算机上使用SSH协议ssh://127.0.0.1，关注kali用户（-l kali），再次使用rockyou词表（-P）：

```
hydra -l kali -P /usr/share/wordlists/rockyou.txt ssh://127.0.0.1
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606820771457-30f2d435-c238-4f2c-81e6-721b095b48e6.png?x-oss-process=image%2Fresize%2Cw_1500)

THC-Hydra支持许多标准协议和服务，如下所示：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606820828499-34f78975-3001-4f1d-8d30-5c0217fb8cfc.png?x-oss-process=image%2Fresize%2Cw_1500)

### HTTP POST Attack with THC-Hydra

作为另一个例子，我们将使用Hydra对我们的Windows Apache服务器执行http post攻击。当http post请求用于用户登录时，通常是通过使用web表单，这意味着我们应该使用“http-form-post”服务模块。我们可以提供后跟-U的服务名称，以获取有关所需参数的其他信息：

```
hydra http-form-post -U
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606821167535-d8616fd6-c97a-4925-b1f2-31041837ebf9.png?x-oss-process=image%2Fresize%2Cw_1500)

我们需要从应用程序中提供一些参数，以确定执行此操作所需的一些参数。首先，我们需要在我们的Windows客户端上包含web表单的网页的IP地址和URL。IP地址将作为hydra的第一个参数提供。

下一步，我们必须通过检查相关网页的HTML代码（位于/form/login.html）来理解我们想要暴力破解的web表单。

图片显示了右键单击页面并从上下文菜单中选择ViewPageSource之后目标web表单的代码：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606822357139-0f414144-89b6-4755-909f-00142eb08ae4.png)

上述表格/form/login.html页，指示POST请求由/form/user.php处理，这是我们将提供给Hydra的URL。之前图片中显示的语法需要表单参数，在本例中是username和passwd。因为我们用单词表攻击管理员用户登录，所以Hydra的组合参数变成 `/form/user.php:username=admin&passwd=^pass^` ，其中^pass^作为单词列表文件项的占位符。

我们还必须提供条件字符串，以指示何时登录尝试失败。这可以通过尝试几次手动登录尝试来找到。在我们的示例中，web页面返回文本“INVALID LOGIN”，如图所示：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606822587215-dd7c3c59-a5d2-48d9-9616-04ad77de9c27.png)

将这些部分放在一起，我们可以完成http-form-post语法。

```
http-form-post "/form/user.php:username=admin&passwd=^PASS^:INVALID LOGIN"
```

现在可以执行完整的命令。我们将提供admin用户名（-l admin）和wordlist（-P），使用-vV请求详细输出，并在找到第一个成功结果时使用-f停止攻击。此外，我们将提供服务模块名称（http-form-post）及其所需的参数（`"/form/user.php:username=admin&passwd=^PASS^:INVALID LOGIN`），如下所示：

```
hydra 10.211.55.8 http-form-post "/form/user.php:username=admin&passwd=^PASS^:INVALID LOGIN" -l admin -P /usr/share/wordlists/rockyou.txt -vV -f
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606822943420-e0fccae2-23dc-4e83-a83c-0477035fc2aa.png?x-oss-process=image%2Fresize%2Cw_1500)

## 利用密码哈希

接下来，我们将注意力转向集中在密码哈希的使用上的攻击。

加密哈希函数是实现算法的单向函数，该算法在给定任意数据块的情况下，返回称为“哈希值”或“消息摘要”的固定大小的位字符串。密码散列函数最重要的用途之一是在密码验证中的应用。

### 检索密码哈希

大多数使用密码验证机制的系统需要将这些密码本地存储在计算机上。现代身份验证机制通常将密码存储为散列，而不是以明文形式存储密码，以提高安全性。对于网络操作系统来说，更是如此。这意味着在身份验证过程中，用户提供的密码经过哈希处理，并与先前存储的消息摘要进行比较。

hashid是一个有用的工具，可以帮助识别散列类型。要使用它，我们只需运行该工具并粘贴到要标识的哈希中：

```
hashid c43ee559d69bc7f691fe2fbfe8a5ef0a
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606828209685-dc025b89-89d3-4992-a143-80a4acceafcc.png)

```
hashid '$6$l5bL6XIASslBwwUD$bCxeTlbhTH76wE.bI66aMYSeDXKQ8s7JNFwa1s1KkTand6ZsqQKAF3G0tHD9bd59e5NAz/s7DQcAojRTWNpZX0'Analyzing '$6$l5bL6XIASslBwwUD$bCxeTlbhTH76wE.bI66aMYSeDXKQ8s7JNFwa1s1KkTand6ZsqQKAF3G0tHD9bd59e5NAz/s7DQcAojRTWNpZX0'
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606828225871-cb0e42b2-1771-4068-ab1a-bbd682a3f7e4.png)

接下来，让我们检索并分析Kali Linux系统上的一些散列值。许多Linux系统都将用户密码散列存储在/etc/shadow文件中，这需要root权限才能读取：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606828294574-72f66e08-6332-4845-8057-46f49a6d7e3c.png)

在上图中，该行以用户名（root）开头，后跟密码散列。散列被分成子字段，第一个子字段（$6）引用SHA-512算法。下一个子字段是salt，它与明文密码一起使用来创建密码哈希。salt是一个随机值，它与明文密码一起用于计算密码哈希。这可以防止哈希查找攻击，因为密码哈希将根据salt值而变化。

现在让我们把注意力转向Windows目标，讨论如何使用各种散列实现，以及如何在评估期间利用它们。

在Windows系统上，散列用户密码存储在安全帐户管理器（SAM）中。为了阻止离线SAM数据库密码攻击，微软引入了SYSKEY功能（Windows NT 4.0 SP3），它对SAM文件进行了部分加密。

基于Windows NT的操作系统（包括Windows 2003）存储两种不同的密码哈希：LAN Manager（LM）（基于DES）和NT LAN Manager（NTLM）（使用MD4 哈希）。众所周知，LAN Manager非常弱，因为长度超过7个字符的密码被分成两个字符串，并且每一个字符都是单独散列的。每个密码字符串在被哈希之前也被转换为大写，而且，LM哈希系统不包括salts，使得哈希查找攻击成为可能。

从Windows Vista开始，操作系统默认禁用LM并使用NTLM，NTLM除其他外，区分大小写，支持所有Unicode字符，并且不会将哈希分成更小、更弱的部分。但是，存储在SAM数据库中的NTLM散列仍然没有被加盐。

值得一提的是，当操作系统运行时，不能复制SAM数据库，因为Windows内核对文件保留了一个独占的文件系统锁。不过，我们可以使用mimikatz（在另一个模块中有更深入的介绍）来装载旨在转储SAM散列的内存攻击。

> https://github.com/gentilkiwi/mimikatz

除其他外，mimikatz模块有助于从本地安全机构子系统（LSASS）进程内存中提取密码散列。

由于LSASS是在系统用户下运行的特权进程，因此必须从管理命令提示符启动mimikatz。要提取密码哈希，必须首先执行两个命令。第一个是privilege::debug，它启用篡改另一个进程所需的SeDebugPrivilge访问权限。如果此命令失败，那么mimikatz很可能没有使用管理权限执行。

必须了解LSASS是一个系统进程，这意味着它比使用管理权限运行的mimikatz具有更高的权限。为了解决这个问题，我们可以使用token::elevate命令将安全令牌从high integrity（administrator）提升到SYSTEM integrity。如果从SYSTEM Shell启动mimikatz，则不需要执行此步骤。现在让我们逐步完成这个过程：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606829320197-fe879ede-0298-426a-8d4f-34936512d6bc.png?x-oss-process=image%2Fresize%2Cw_1500)

现在我们可以使用lsadump::sam转储sam数据库的内容：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606829398983-d192f764-a942-48bc-8874-9d34ff343a28.png)

其他散列转储工具，包括pwdump、fgdump和Windows凭证编辑器（wce），可以在较旧的Windows操作系统（如windows xp和windows server 2003）上运行良好。

### 在Windows中传递哈希

我们将在下一节中发现，破解密码散列非常耗时，而且在没有强大硬件的情况下通常是不可行的。然而，有时我们可以利用基于windows的密码哈希，而不必求助于费力的破解过程。

Pass-The-Hash（PtH）技术（1997年发现）允许攻击者使用用户名和NTLM/LM哈希的有效组合（而不是明文密码）向远程目标进行身份验证。这是可能的，因为NTLM/LM密码哈希不会被加盐，并且在会话之间保持静态。此外，如果我们在一个目标上发现一个密码哈希，我们不能仅使用它来验证该目标，我们也可以使用它来验证另一个目标，只要该目标有一个用户名和密码相同的帐户。

让我们介绍一个场景来演示这种攻击。在评估期间，我们发现了一个在多个系统上启用的本地管理帐户。我们利用其中一个系统上的漏洞并获得了系统权限，从而可以转储本地LM和NTLM哈希。我们已经复制了本地管理员NTLM哈希，现在可以使用它代替密码来访问另一台具有相同本地管理员帐户和密码的计算机。

为此，我们将使用Passing the Hash toolkit（winexe的修改版本）中的pth-winexe ，它使用SMB协议执行身份验证：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606829835171-086bddd3-ea88-411c-8847-373878ef377b.png)

在计算机上使用cmd等远程应用程序需要管理权限。这是由于对管理共享C$的身份验证以及随后创建的Windows服务。

作为一个演示，我们将在Kali机器上调用pth-winexe，使用先前转储的密码散列对目标进行身份验证。在指定SMB命令的名称时，我们将在命令中指定SMB的名称，并在命令中指定SMB的名称。我们将忽略DOMAIN参数，并将用户名（后跟一个%符号）添加到哈希中以完成命令。语法有点棘手，如下所示：

```
pth-winexe -U soft98%aad3b435b51404eeaad3b435b51404ee:a80d2ad0380ff7603e9a44124de107d5 //10.211.55.8 cmd
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606831301101-a2d2182f-f254-469b-bae2-7c7f3acf7f99.png)

如果出现下面的错误，可以以管理员身份运行cmd，然后执行指令 `reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\system" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f` 

E_md4hash wrapper called.

ERROR: CreateService failed. NT_STATUS_ACCESS_DENIED.

在幕后，我们提供的NTLM哈希的格式在身份验证过程中被更改为NetNTLM版本1或2格式。我们可以使用中间人攻击或中毒攻击捕获这些哈希值，并将其破解或中继它们。

例如，Internet Explorer和Windows Defender等应用程序使用Web代理自动发现协议（WPAD）来检测代理设置。如果我们在本地网络上，我们可以毒害这些请求，并使用类似于Responder.py，创建了一个恶意WPAD服务器，旨在利用此安全问题进行攻击。由于中毒对其他用户的破坏性很大，因此Responder.py绝对不能在实验室里使用。

> https://github.com/SpiderLabs/Responder

### 密码破解

在密码分析中，密码破解是给定其存储的哈希值，恢复明文密码短语的过程。

密码破解的过程在高层相当直接。一旦我们发现了在目标身份验证过程中处理的哈希机制，我们就可以迭代单词列表中的每个单词并生成相应的消息摘要。如果计算出的哈希值与从目标系统获得的哈希值相匹配，我们就获得了匹配的纯文本密码。这通常都是在一个专门的密码破解程序的帮助下完成的。

如果身份验证过程中涉及salt，并且我们不知道salt值是什么，那么破解可能变得非常复杂，如果不是不可能的话，我们必须用各种盐反复散列每个潜在的明文密码。

然而，根据我们的经验，无论是来自每个记录都包含两个唯一值的数据库，还是来自对所有哈希值使用单一salt的配置或二进制文件，我们几乎总是能够捕捉到密码散列和salt。当这两个值都已知时，密码破解的复杂性就会降低。

一旦我们从目标系统获得了密码散列的访问权，我们就可以开始一个密码破解会话，在后台运行，同时继续我们的评估。如果任何一个密码被破解，我们可以尝试在其他系统上使用这些密码来加强我们对目标网络的控制。我们会像之前的测试一样，把数据反馈到其他的过程中。

为了演示密码破解，我们将再次转向john the ripper，因为它支持几十种密码格式，而且功能强大且灵活。

在纯暴力模式下运行john（尝试在密码中进行所有可能的字符组合）就像在命令行上传递包含密码哈希的文件名和哈希格式一样简单。

在下面，我们攻击使用mimikatz转储的NT散列（--format=NT）。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606832193756-164d609d-2f65-45d0-b327-c8cf1dc7eee6.png)

在上面的输出中，JTR正确地识别了散列类型并着手破解它。然而，基于我们系统的速度，像这样的暴力攻击需要很长时间。另一种方法是，我们可以使用--wordlist参数并提供指向单词列表的路径，这样可以缩短处理时间，但可以减少密码覆盖范围：

```
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt --format=NT
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606832791535-e14c34dd-5616-41b1-8fe5-c92aa02dc85f.png)

如果仍有任何密码需要破解，我们接下来可以尝试使用--rules参数应用JTR的单词混乱规则：

```
john --rules --wordlist=/usr/share/wordlists/rockyou.txt hash.txt --format=NT
```

为了用JTR破解基于Linux的散列，我们需要首先使用unshadow实用程序来组合来自受损系统的passwd和shadow文件。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606834561662-f378ddf4-6db6-4ec1-867c-449c4efd32bf.png?x-oss-process=image%2Fresize%2Cw_1500)

我们现在可以运行john，将单词列表和未着色的文本文件作为参数传递：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606834613356-2565a857-1004-495e-a113-228e450922ec.png?x-oss-process=image%2Fresize%2Cw_1500)

新版本的john the ripper默认情况下是多线程的，但是旧版本只使用一个CPU内核来执行破解操作。如果遇到较旧版本的JTR，它支持可以加快进程的替代方案。我们可以使用多个CPU核心，甚至多台计算机来分配负载并加快破解过程。--fork选项使用多个进程来在一台机器上使用更多的CPU核心，--node在多台机器上分割工作。

例如，假设我们有两台机器，每台都有一个8核CPU。在第一台机器上，我们将设置--fork=8和--node=1-8/16选项，指示John在这台机器上创建8个进程，将提供的单词表分成16个相等的部分，并在本地处理前8个部分。在第二台机器上，我们可以使用--fork=8和--node=9-16来分配8个进程到单词表的后半部分。以这种方式划分工作将提供大约16倍的性能改进。

攻击者还可以预先计算密码的哈希值（这可能需要很长时间），并将其存储在一个庞大的数据库或彩虹表中，使密码破解成为一个简单的表查找事件。这是一种空间-时间的权衡，因为这些表可能会消耗大量的空间（根据密码的复杂程度，可以达到数PB），但是密码“破解”过程本身（技术上是一个查找过程）所需的时间要少得多。

Hashcat的选项通常与（john the ripper）相似，并包括算法检测和密码列表变异等功能。而且可以利用CPU和GPU的计算能力，所以会比john快上很多。