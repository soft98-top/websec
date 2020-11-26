# 16-Privilege Escalation

## 信息收集

### 手动枚举

#### 枚举用户

`whoami` 是一个通用的命令

windows下，可以用 `net user` 进行查看用户信息。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606379660151-5cf2226d-df2a-4126-836d-3a8accdb3141.png)

基于Linux的系统，可以用 `id` 进行收集用户信息：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606379893618-66fd1ebe-9cca-4ac2-a0ed-73780b96b4b1.png)

`net user` 不带任何信息，就可以输出其它的用户账户

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606380002049-3ccc66ee-57a9-41c4-abb3-e52b6ccc3423.png)

linux下，直接读取/etc/passwd文件即可：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606380033250-fd111e46-73c3-473e-b5f7-3d78fc47f906.png)

passwd文件列出了几个用户帐户，包括目标计算机上各种服务（如www data）使用的帐户，这表明可能安装了web服务器。

枚举目标计算机上的所有用户有助于识别潜在的高权限用户帐户，我们可以针对这些帐户尝试提升权限。

#### 枚举主机名

计算机的主机名通常可以提供有关其功能角色的线索。主机名通常包括可识别的缩写，例如web服务器的web、数据库服务器的db、域控制器的dc等。

利用 `hostname` 命令，通用。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606380180128-bdc4c654-bbf1-49a6-bedf-ce81320fb5f4.png)

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606380191821-cc03068b-e8c5-4034-8ac5-4ac968a669dd.png)

#### 枚举操作系统版本和体系结构

在权限提升过程中的某个时刻，我们可能需要依赖内核漏洞攻击，这些漏洞专门利用目标操作系统核心中的漏洞。这些类型的攻击是为特定类型的目标而构建的，由特定的操作系统和版本组合指定。由于使用不匹配的内核漏洞攻击目标会导致系统不稳定（导致访问丢失，并可能会警告系统管理员），因此我们必须收集有关目标的精确信息。

在Windows操作系统上，我们可以使用 `systeminfo` 实用程序收集特定的操作系统和体系结构信息。

我们还可以使用 `findstr` 和一些有用的标志来过滤输出。具体来说，我们可以用/B匹配行首的模式，并使用/C:指定特定的搜索字符串。

```
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
systeminfo | findstr /B /C:"OS 名称" /C:"OS 版本"
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606380537553-f4666f05-fc34-4134-9a79-317b3c754291.png)

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606380570004-c04bc9d2-7666-437e-92a8-2d7608e7425b.png)

在Linux上， `/etc/issue` 和 `/etc/*-release` 文件包含类似的信息。我们也可以发出 `uname -a` 命令：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606380736020-e29f7c1a-c5b8-4867-a2a9-aa88cd2a6d27.png)

#### 枚举正在运行的进程和服务

我们可以用 `tasklist` 命令列出Windows上正在运行的进程。 `/SVC` 标志将返回映射到特定Windows服务的进程。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606380856144-48a37fd9-ea35-48cf-877c-5e8c3759d749.png)

在Linux上，我们可以使用 `ps` 命令列出系统进程（包括特权用户运行的进程）。我们将使用 a 和 x 标志列出带有或不带有tty的所有进程，使用 u 标志以用户可读的格式列出进程。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606380983740-636c1af9-56f9-4a0e-a317-12605da3affd.png)

#### 枚举网络信息

我们可以使用 `ipconfig` 开始在Windows操作系统上收集信息，使用 `/all` 标志显示所有适配器的完整TCP/IP配置。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606381156962-cc03e173-7bb8-4399-837a-05c96ac7d30a.png)

为了显示网络路由表，我们将使用 `route` 命令和 `print` 参数。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606381257305-7af6f34c-4cbb-4c33-ba8a-2e68f80c3d48.png)

最后，我们可以使用 `netstat` 来查看活动的网络连接。指定 a 标志将显示所有活动的TCP连接，n 标志允许我们以数字形式显示地址和端口号，o 标志将显示每个连接的所有者PID。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606381336365-142cf4cb-9ffa-4ed3-87fd-04a3f3978001.png)

`netstat` 不仅向我们提供了机器上所有监听端口的列表，还包括有关已建立连接的信息，这些信息可能会显示连接到这台机器的其他用户，我们以后可能会将其作为目标。

在基于Linux的主机上也可以使用类似的命令。根据Linux的版本，我们可以列出每个网络适配器的TCP/IP配置，其中包括 `ifconfig` 或 `ip` 。这两个命令都接受 a 标志以显示所有可用信息。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606381479685-0cbde38c-934c-42cd-b32e-f51ec1bf585c.png)

根据Linux风格和版本，我们可以使用 `route` 或 `routel` 显示网络路由表。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606381579180-a75b2324-9728-4e96-82ca-b32f005dd984.png)

最后，我们可以用 `netstat` 或 `ss` 来显示活动的网络连接和监听端口，这两个端口都接受相同的参数。

例如，我们可以用 `-a` 列出所有连接，用 `-n` 避免主机名解析（这可能会暂停命令执行），并用 `-p` 列出连接所属的进程名。我们可以合并参数，只需运行 `ss -anp` ：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606381868070-3ddaf7d4-0238-4673-a20c-c8a097b648a1.png)

#### 枚举防火墙状态和规则

一般来说，防火墙的状态、配置文件和规则只在评估的远程利用阶段感兴趣。但是，此信息在权限提升期间可能很有用。例如，如果网络服务由于被防火墙阻止而无法远程访问，则通常可以通过环回接口在本地访问该服务。如果我们可以在本地与这些服务交互，我们就可以利用它们来提升我们在本地系统上的权限。

此外，在这个阶段，我们可以收集有关入站和出站端口筛选的信息，以便在需要转到内部网络时进行端口转发和隧道传输。

在Windows上，我们可以使用 `netsh` 命令检查当前的防火墙配置文件。

```
netsh advdirewall show currentprofile
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606382010300-bbf1234b-0ddb-4759-84fd-563740a33216.png)

在本例中，当前的防火墙配置文件是活动的，所以让我们仔细看看防火墙规则。

我们可以使用 `netsh` 命令使用以下语法列出防火墙规则：

```
netsh advfirewall firewall show rule name=all
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606382196317-b45a5d49-3ed8-4c9a-88a3-98428858ee8c.png)

在基于Linux的系统上，我们必须具有root权限才能使用 `iptables` 列出防火墙规则。然而，根据防火墙的配置方式，作为一个标准用户，我们可能能够收集有关规则的信息。

我们还可以搜索 `iptables save` 命令创建的文件，该命令用于将防火墙配置转储到用户指定的文件中。然后，该文件通常用作 `iptables restore` 命令的输入，并用于在引导时还原防火墙规则。如果系统管理员曾经运行过这个命令，我们可以搜索配置目录（/etc）或grep文件系统中的iptables命令来定位该文件。如果文件具有不安全的权限，我们可以使用这些内容来推断系统上运行的防火墙配置规则。

#### 枚举计划任务

攻击者通常在权限提升攻击中利用计划任务。

作为服务器的系统通常定期执行各种自动化、计划的任务。这些服务器上的调度系统通常有一些混乱的语法，用于执行用户创建的可执行文件或脚本。当这些系统配置错误，或者用户创建的文件没有安全权限时，我们可以修改这些文件，这些文件将由调度系统在高权限级别执行。

我们可以使用 `schtasks` 命令在Windows上创建和查看计划任务。 `/query` 参数显示任务， `/FO LIST` 将输出格式设置为简单列表。我们还可以使用 `/V` 请求详细的输出。

```
schtasks /query /fo LIST /v
```

效果类似下面这个，我的靶机上出了错误：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606382778624-4d953a11-f51e-4bd9-8d72-09fedbe93985.png)

`schtasks` 生成的输出包含许多有用的信息，例如要运行的任务、下一次运行的时间、上次运行的时间以及运行频率的详细信息。

基于Linux的作业调度程序称为Cron。计划任务列在 `/etc/cron.*` 目录下，其中*表示任务运行的频率。例如，每天运行的任务可以在/etc下找到 `/cron.daily` . 每个脚本都列在它自己的子目录中。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606382947775-e0e72858-6bd2-4b1a-bbf7-ef07665354c3.png)

在列出目录内容时，我们注意到有几个任务计划每天运行。

值得注意的是，系统管理员经常在 `/etc/crontab` 文件中添加他们自己的计划任务。应该仔细检查这些任务是否具有不安全的文件权限，因为此特定文件中的大多数作业将以根用户身份运行。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606387595002-47026ddc-056b-4b33-9b3e-13dff1eae8f9.png)

这个例子展示了一个以root用户身份运行的备份脚本。如果此文件具有弱权限，我们可以利用它来提升我们的权限。

#### 枚举已安装的应用程序和修补程序级别

在某些时候，我们可能需要利用漏洞来提升我们的本地权限。如果是这样的话，我们将从枚举所有已安装的应用程序开始寻找有效的漏洞，并注明每个应用程序的版本（以及基于Windows的系统上的操作系统修补程序级别）。我们可以使用此信息搜索匹配的攻击。

`wmic` 实用程序提供对Windows管理工具的访问，后者是Windows上管理数据和操作的基础设施。

我们可以将 `wmic` 与 `product` WMI类参数一起使用，后跟 `get` ，顾名思义，get用于检索特定的属性值。然后我们可以选择我们感兴趣的属性，例如名称、版本和供应商。

要记住的一件重要事情是， `product` WMI类只列出了由Windows安装程序安装的应用程序。它不会列出不使用Windows安装程序的应用程序。

```
wmic product get name, version, vendor
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606387930980-749e1c32-864a-4243-809c-4d6ee2200bb6.png)

同样，更重要的是，wmic还可以通过查询Win32_QuickFixEngineering（qfe）wmi类来列出系统范围的更新。

```
wmic qfe get Caption, Description, HotFixID, InstalledOn
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606388091555-7f093298-fab5-4d26-ad51-febf8e1dad5e.png)

HotFixID和InstalledOn信息的组合可以为我们提供目标Windows操作系统的安全态势的精确指示。根据这个输出，这个系统最近没有更新，这可能会使它更容易被利用。

基于Linux的系统使用各种包管理器。例如，基于Debian的Linux发行版使用dpkg，而基于redhat的系统使用rpm。

要列出Debian系统上安装的应用程序（由dpkg安装），我们可以使用 `dpkg -l` 。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606388181894-aa7f6c78-78b4-4e37-a5d7-a4de23537b89.png)

#### 枚举可读写文件和目录

如前所述，访问限制不足的文件可能会创建一个漏洞，该漏洞可授予攻击者提升的权限。当攻击者可以修改在特权帐户上下文下执行的脚本或二进制文件时，通常会发生这种情况。

有许多实用程序和工具可以在Windows平台上为我们自动执行此任务。SysInternals中的AccessChk可以说是最著名、最常用的工具。

> AccessChk：https://docs.microsoft.com/zh-cn/sysinternals/downloads/accesschk

我们将使用 `-u` 来抑制错误， `-w` 用于搜索写访问权限，使用 `-s` 执行递归搜索。其他选项也值得探讨，因为这个工具非常有用。

我的电脑上没有，所以没有查询出结果。

```
accesschk.exe -uws "Everyone" "C:\Program Files"
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606391608842-8b366bbd-0f16-4381-8ddc-d51eefb591f1.png)

如果有的话，会有下面的效果：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606391659595-9ba56fdb-1548-4d57-9d83-f3a4c0b9c120.png)

我们也可以使用PowerShell实现相同的目标。这在我们可能无法在目标系统上传输和执行任意二进制文件的情况下非常有用。

```
Get-ChildItem "C:\Program Files" -R ecurse | Get-ACL | ?{$_.AccessToString -match "Everyone\sAllow\s\sModify"}
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606391895040-12ad26a7-ecd3-4f97-9eb2-d0a064af98e3.png)

在Linux操作系统上，我们可以使用 `find` 来识别具有不安全权限的文件。

在下面的示例中，我们搜索目标系统上当前用户可写的每个目录。我们搜索整个根目录（/）并使用 `-writable` 参数指定我们感兴趣的属性。我们还使用 `-typed` 来定位目录，并使用 `2>/dev/null` 过滤错误：

```
find / -writable -type d 2>/dev/null
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606392157715-9bff6c10-239b-4a2f-b869-bb41d84293dc.png)

#### 枚举未装载的磁盘

在大多数系统中，驱动器是在引导时自动安装的。因此，很容易忘记未安装的驱动器，这些驱动器可能包含有价值的信息。我们应该始终查找未装载的驱动器，如果存在，请检查装载权限。

在基于Windows的系统上，我们可以使用 `mountvol` 列出当前安装的所有驱动器以及物理连接但未安装的驱动器。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606392275013-0e81053e-e9e1-4d58-b25e-d3db2d8a6bae.png)

在基于Linux的系统上，我们可以使用 `mount` 命令列出所有挂载的文件系统。此外， `/etc/fstab` 文件列出了引导时将安装的所有驱动器。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606392335374-8ac190e2-0d70-43c5-ab6f-58703da12d66.png)

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606392355852-1272e11a-d810-4703-ba3d-436bf976f6b5.png)

我们可以使用 `lsblk` 查看所有可用磁盘。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606392500495-84832587-afdf-489d-b8c7-c8a636256ef9.png)

#### 枚举设备驱动程序和内核模块

另一种常见的权限提升涉及设备驱动程序和内核模块的攻击。我们将在本模块后面介绍实际的利用技术，但让我们看一看重要的枚举技术。由于该技术依赖于将漏洞与相应漏洞进行匹配，因此我们需要编译一个加载到目标上的驱动程序和内核模块的列表。

在Windows上，我们可以用 `driverquery` 命令开始搜索。我们将为详细输出提供 `/v` 参数，以及 `/fo csv` 以csv格式请求输出。

为了过滤输出，我们将在PowerShell会话中运行此命令。在PowerShell中，我们将输出通过管道传输到 `ConvertFrom Csv` cmdlet以及 `Select Object ` ，这将允许我们选择特定的对象属性或对象集，包括显示名称、启动模式和路径。

```
driverquery.exe /v /fo csv | ConvertFrom-CSV | Select-Object ‘Display Name’, ‘Start Mode’, Path
```

ConvertFrom-CSV会报错，所以就看一下前面的效果吧，后面的就是过滤的：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606393763798-7240f0dd-12a6-477c-b208-d34e608f34b9.png)

类似这种效果：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606393817761-8f335f37-da72-40d7-bd18-32fbf86ec960.png)

虽然这产生了一个已加载驱动程序的列表，但我们必须采取另一个步骤来请求每个加载的驱动程序的版本号。我们将使用 `Get-WmiObject` cmdlet获取Win32_pnpsignedriver WMI实例，该实例提供有关驱动程序的数字签名信息。通过管道输出到 `Select Object` ，我们可以枚举特定属性，包括驱动版本。此外，我们可以通过管道将输出发送到 `Where-Object` ，从而根据驱动程序的名称来确定驱动程序的目标.

```
Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, Manufacturer | Where-Object {$_.DeviceName -like "*VMware*"}
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606394569629-2731e232-65cb-4d61-8bb6-06c0dc8076ba.png)

在Linux上，我们可以使用 `lsmod` 枚举加载的内核模块，而不需要任何额外的参数。![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606394641753-4201b63b-b2a7-403c-bb39-8b6ec97bf6ab.png)

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606394840670-d491ae86-a249-498a-9374-0182c14c6ca5.png)

一旦我们有了已加载模块的列表并确定了需要更多信息的模块，比如上面示例中的libata，我们就可以使用 `modinfo` 来了解有关特定模块的更多信息。请注意，此工具需要完整的路径名才能运行。

```
/sbin/modinfo libata
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606394888912-a861a06f-9210-469f-bcc0-317a7912dd0f.png)

#### 枚举自动升级的二进制文件

在本模块的后面，我们将探讨各种权限提升方法。然而，在本节中，我们应该讨论一些特定于操作系统的枚举，它们可以揭示特权提升的有趣的特定于操作系统的“捷径”。

首先，在Windows系统上，我们应该检查AlwaysInstallElevated注册表设置的状态。如果在计算机中启用了HKEY_CURRENT_USER或HKEY_LOCAL_MACHINE（设置为1），则任何用户都可以使用提升的权限运行Windows Installer软件包。下面的命令我没有成功，提示系统找不到指定的注册表。

```
reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606396230040-41aefd98-500b-42b3-b2e5-fda750627435.png)

如果启用了这个设置，我们可以创建一个MSI文件并运行它来提升我们的特权。

类似地，在基于Linux的系统上，我们可以搜索suid文件。

通常，在运行可执行文件时，它继承运行它的用户的权限。但是，如果设置了SUID权限，则二进制文件将以文件所有者的权限运行。这意味着，如果一个二进制文件设置了SUID位，并且该文件属于root用户，则任何本地用户都可以使用提升的权限执行该二进制文件。

我们可以使用find命令搜索SUID标记的二进制文件。在本例中，我们从根目录（/）开始搜索，查找SUID位设置为（-perm -u=s）的文件（-type f），并丢弃所有错误消息（2>/dev/null）：

```
find / -perm -u=s -type f 2>/dev/null
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606396490180-0b10abbc-3c53-4ee8-bff7-f58aa59d3f3b.png)

在本例中，命令找到了几个SUID二进制文件。SUID二进制文件的利用将因几个因素而有所不同。例如，如果/bin/cp（copy命令）是SUID，我们可以复制和覆盖敏感文件，如/etc/passwd。

### 自动枚举

在Windows上，一个这样的脚本是windows-privesc-check，可以在windows-privesc-check Github存储库中找到。仓库已经包含了一个由PyInstaller生成的Windows可执行文件，但也可以根据需要重新构建它。

> https://github.com/pentestmonkey/windows-privesc-check

运行带有 `-h` 标志的可执行文件将显示以下帮助菜单：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606397389661-70335c83-10f1-4c52-b38d-48ef89ff9593.png)

这个工具接受许多选项，但是我们将简单介绍一些示例。首先，我们将列出有关系统上用户组的信息。我们将指定 `--dump` 来查看输出，并指定 `-G` 来列出组。

```
windows-privesc-check2.exe --dump -G
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606397504773-bb911449-a576-4d53-9498-f3514c601189.png)

与windows目标上的windows-privesc-check类似，我们也可以在unix衍生工具（如Linux）上使用unix_privesc_check。我们可以通过运行不带任何参数的脚本来查看工具帮助。

> http://pentestmonkey.net/tools/audit/unix-privesc-check

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606399155166-54d9630a-df0e-49ae-82bd-f996451b3b52.png)

如上面的清单所示，脚本支持“标准”和“详细”模式。根据所提供的信息，标准模式似乎在执行速度优化的过程，并且应该提供较少的误报。因此，在下面的示例中，我们将使用标准模式并将整个输出重定向到名为otput.txt.

```
./unix-privesc-check standard > output.txt
```

该脚本对公共文件执行多次权限检查。例如，以下摘录显示了非root用户可写的配置文件：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606399332262-61ac6caf-998a-48a2-85e4-1905d6715c51.png)

## Windows权限提升示例

在本节中，我们将讨论Windows特权、完整性机制和用户帐户控制（UAC）。我们将演示UAC绕过技术，并利用内核驱动程序漏洞、不安全的文件权限和未加引号的服务路径来提升我们在目标系统上的权限。

### 了解Windows权限和完整性级别

Windows操作系统上的权限是指特定帐户执行与系统相关的本地操作的权限。这包括修改文件系统、添加用户、关闭系统等操作。

为了使这些特权有效，Windows操作系统使用称为访问令牌的对象。496一旦用户通过身份验证，Windows将生成一个访问令牌分配给该用户。令牌本身包含各种信息，这些信息有效地描述了给定用户的安全上下文，包括用户权限。

最后，考虑到它们包含的信息，这些令牌需要是唯一可识别的。这是使用安全标识符或SID来完成的，SID是分配给每个对象（包括令牌）的唯一值，例如用户或组帐户。

这些SID由Windows本地安全机构生成和维护。

除了特权之外，Windows还实现了所谓的完整性机制。这是Windows安全体系结构的核心组件，通过为应用程序进程和安全对象分配完整性级别来工作。简单地说，这描述了操作系统在运行应用程序或安全对象时的信任级别。例如，配置的完整性级别指示应用程序可以执行的操作，包括读取或写入本地文件系统的能力。API也可以从特定的完整性级别阻止。

从Windows Vista开始，进程在四个完整性级别上运行：

• System integrity process: SYSTEM rights

• High integrity process: administrative rights

• Medium integrity process: standard user rights

• Low integrity process: very restricted rights often used in sandboxed processes

### 用户帐户控制（UAC）简介

用户帐户控制（UAC是微软在window svista和windows server 2008中引入的一种访问控制系统。虽然UAC已经被讨论和调查了很长一段时间，但必须强调的是，微软并不认为它是一个安全边界。相反，UAC强制应用程序和任务在非管理帐户的上下文中运行，直到管理员授权提升的访问权限。它将阻止安装程序和未经授权的应用程序在没有管理帐户权限的情况下运行，并阻止对系统设置的更改。一般来说，UAC的效果是，任何希望执行对系统有潜在影响的操作的应用程序都不能安静地执行。至少在理论上。

还需要强调的是，UAC有两种不同的模式：凭证提示和同意提示。区别很简单。当标准用户希望执行管理任务（如安装新应用程序）并且启用了UAC时，用户将看到凭证提示。换句话说，需要管理用户的凭据才能完成任务。但是，当管理用户尝试执行相同操作时，他或她将出示同意提示。在这种情况下，用户只需确认任务应该完成，不需要重新输入用户凭证。

例如，在下图中，在标准用户帐户下运行的Windows命令处理器正在尝试执行特权操作。UAC根据其通知设置（在这种情况下总是通知）来操作，暂停目标进程cmd.exe并提示输入管理员用户名和密码以执行请求的特权操作。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606402551802-615fffba-0893-4a5d-9b92-fc39472f1766.png)

即使以管理用户身份登录，帐户也会有两个安全令牌，一个在中等完整性级别运行，另一个在高完整性级别运行。UAC充当这两个完整性级别之间的分离机制。

要查看实际的完整性级别，首先以admin用户身份登录，打开命令提示符，然后运行 `whoami /groups` 命令：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606403076845-bab3a782-7f3d-482c-b06e-24c518aa4b84.png)

可以看到最后一行，我们当前是一个Medium级别的完整性级别，然后我们尝试修改用户的密码。

```
net user soft98 www.soft98.top
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606403149402-77f2961b-3516-4135-b966-861dba3048a7.png)

请求被拒绝，即使我们以管理用户身份登录。

为了更改管理员用户的密码，即使使用管理用户登录，我们也必须切换到高完整性级别。在我们的示例中，一种方法是通过powershell.exe使用Start Process  cmdlet指定“以管理员身份运行”选项：

```
powershell.exe Start-Process cmd.exe -Verb runAs
```

会出现一个UAC提示，我们同意之后会弹出一个以管理员身份运行的cmd.exe：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606403358404-c37e020a-45b5-448b-ac31-975e6884063b.png)

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606403393703-d92a287d-15f1-4d4d-820b-768a6564232b.png)

这时候我们再用 `whoami /groups` 查看一下，会发现是在高完整性等级之下

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606403435584-6d9442e0-c529-40ad-8540-d8e97a1a3663.png)

这时候再执行修改用户密码：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606403497250-7174cb59-c583-4be2-919d-9749f3cacfe4.png)

### 用户帐户控制（UAC）Bypass：fodhelper.exe文件案例研究