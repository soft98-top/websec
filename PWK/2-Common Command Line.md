# 2-Common Command Line

## Bash 环境

### 环境变量

$PATH 配置路径，里面默认保存一些命令的目录，which查询依赖于这个变量的值。

$USER 存储当前用户名

$PWD 存储当前目录的路径

$HOME 存储当前用户的主目录路径

$$ 当前shell实例的进程ID

...

定义变量用 export 变量名=变量值

env 显示在Kali LInux中默认定义的变量

## Tab 补齐

输入命令前几个字母按 tab 自动补齐，但是如果有多个命令的时候是没有效果的，按两下 tab 会列出所有可能的命令。

在命令的选项部分，按 tab 会补齐选项，两下出现所有可能的选项。

在参数的位置，比如文件，输入文件名字的前几个字，按 tab 会自动补齐位于在当前目录下的文件名，两下会出现所有的可能。

## history

history命令会列出曾经输入的命令的历史记录。

ctrl + r 可以在历史记录中搜索输入过的命令行。

## 管道和重定向

### 重定向到新文件

将输出写入到一个文件中，用 > 进行连接，前面是产出内容的，后面是接受内容的文件，后面的文件名如果不存在，系统会自动创建一个，如果已经存在，文件的内容会被完全覆盖。

例如：echo "this is a redirection test" > redirection_test.txt

### 重定向到已存在的文件

与上一个一样，只不过使用 >> 连接，其实是一样的意思，只不过是不要讲已经存在的文件内容完全覆盖，而是在文件后面进行添加。

例如：echo "this is the second line" >> redirection_test.txt

### 从文件中重定向出来

前面命令行需要一个输入，而输入从后面的文件中读取，用 < 连接，说白了箭头的方向就代表着数据的流动方向。

例如 wc -m < redirection_test.txt

wc 是一个统计的工具。

### 重定向 STDERR

根据标准，有标准输入 STDIN，标准输出 STDOUT，和标准错误输出 STDERR，然后从左到右被定义为 0，1，2。

比如查询一个不存在的目录，然后将报错信息输出到文件。

例如：ls ./noexist 2>error.txt

### 管道

管道用于在命令之间传输数据，将前一个命令的标准输出传送给下一个命令使用过。

例如：cat error.txt | wc -m

## 文本搜索和操作

### grep

grep用于匹配指定的文本或正则表达式，然后输出，功能很强大，建议后续自己去多了解。

例如：ls -al /usr/bin | grep zip

### sed

sed是一个强大的数据流编辑器，用法很多，可以进行替换等等。

例如：echo "I need to try hard" | sed 's/hard/harder/'

这个例子的输入会将hard替换为harder。

### cut

cut是一个比较简单的工具，但是经常排上用场，它用于将文本分割成片段，匹配的分隔符用 -d 指定，-f 显示指定位置的文本，从 1 开始。

例如：echo "www.soft98.top" | cut -d "." -f 2

### awk

awk 是一种为文本处理设计的编程语言，通常用作数据提取和报告工具。它很强大，但是很复杂，所以需要一段时间去琢磨，常规用法就是在有输入的情况下，-F 指定匹配的分割字符，然后跟随语句，一边为 '{语句}'。

例如：echo "hello::there::friend" | awk -F "::" '{print $1,$3}'

### Example

分析apache2的访问日志。

查看访问日志的记录格式

head access.log

瞄一眼有多少行

wc -l access.log

将所有的访问IP都罗列出来

cat access.log | cut -d " " -f 1 | sort -u

将所有的访问IP的访问次数也列出来

cat access.log | cut -d " " -f 1 | sort | uniq -c | sort -urn

找出访问可疑的IP之后，查看他访问的页面

cat access.log | grep 'xxx.xxx.xxx.xxx' | cut -d "\"" -f 2| uniq -c

比如想查看他访问的有关admin页面的记录

cat access.log | grep 'xxx.xxx.xxx.xxx' | grep '/admin' | sort -u

搜索一下对方有没有搜索过不是admin页面的记录

cat access.log | grep 'xxx.xxx.xxx.xxx' | grep -v '/admin'

## 从命令行编辑文件

### nano

nano是一款使用简单的文本编辑器，直接 nano 文件名就可以打开文件进行编辑，界面下方也有相应的快捷键提示。^代表的是ctrl。

### vi

vi是一个非常强大的文本编辑器，速度非常快，特别是在自动化重复任务时。使用方法就是 vi 文件名。更多功能自行研究。

它有命令模式和编辑模式，按 i 进入编辑模式，esc 返回命令模式，默认为命令模式。命令模式下 dd 删除光标当前行，yy 拷贝当前行，p 粘贴，x 删除当前字符，:w 保存，:q! 强制退出不保存修改，:wq 保存并退出。

## 比较文件

### comm

comm命令比较两个文本文件，显示每个文件唯一的行以及它们共有的行。用法 comm 文件1 文件2，显示一共有三列，第一列为文件1独有，第二列为文件2独有，第三列为两个文件共有的。可以加选项 -n ，n可以为1，2，3的单独数字或组合，可以理解为减去哪几列。

例如显示文件1独有的行：comm -23 file1.txt file2.txt

### diff

diff命令用于检测文件之间的差异，类似于comm命令。但是，diff要复杂得多，并且支持多种输出格式。最流行的两种格式包括上下文格式(-c)和统一格式(-u)。

用法：diff -c/-u 文件1 文件2

显示出来的 - 号为第一个文件独有，+号为第二个文件独有。

### vimdiff

vimdiff明令将多个文件用vim打开，显示在同一个窗口下，然后文件之间的不同会被高亮显示。

用法 vimdiff 文件1 文件2

## 管理 Processes

### 后台处理

命令最后加一个&，会自动转到后台执行。

ctrl + z，会将当前执行的进程暂停

bg 移动任务至后台，将 JOB_SPEC 标识的任务放至后台，就像它们是带 `&' 启动的一样。如果 JOB_SPEC 不存在，shell 观念中的当前任务将会被使用。

### Jobs控制和fg命令

jobs 会列出当前会话终端下运行的作业，fg 可以将后台运行的作业移至前台。jobs 列出的后台作业，会有标号，可以用 fg %1将第一个移至前台，只有一个作业的情况下可以不带参数。这个 %后面还有加的内容还有多种用法，可以自己去搜一下。

### 过程控制:ps和kill

ps 列出了系统范围内的进程，而不仅仅是当前终端会话。内容太多了，自己去看一下文档。

常用 ps -ef 、ps aux 、ps -fC 关键词

kill 就是终止进程，后面跟上进程的PID。

## 文件和命令监视

### tail

tail 最常见的用途是监视正在写入的日志文件条目。也可以用于查看文件后几行的数据，查看数据是跟head对应的。

例如 sudo tail -f /var/log/apache2/access.log

### watch

watch 命令用于定期运行一个指定的命令。默认情况下，它每两秒运行一次，但是我们可以通过使用-n X选项指定一个不同的间隔，让它每“X”秒运行一次。

例如每五秒执行一次列出当前登录的用户（通过 w 指令）。

watch -n 5 w

## 文件下载

### wget

wget 命令(我们将大量使用它)使用HTTP/HTTPS和FTP协议下载文件。可以用 -O 指定保存的文件名。

用法：wget -O 保存的文件名 下载的地址

### curl

curl 是一个工具，可以使用包括IMAP/S、POP3/S、SCP、SFTP、SMB/S、SMTP/S、TELNET、TFTP和其他协议向服务器传输数据。渗透测试人员可以使用它来下载或上传文件，并构建复杂的请求。它最基本的用法与wget非常相似。用 -o 指定保存的文件名，curl是小写o，wget是大写O。

### axel

axel 是一个下载加速器，通过多个连接从FTP或HTTP服务器传输文件。这个工具有大量的特性，但是最常见的是-n，它用于指定要使用的多个连接的数量。-a选项显示一个简洁的进度指示器，使用-o为下载的文件指定不同的文件名。

例如 axel -a -n 连接数 -o 保存的文件名 下载地址

## 自定义Bash环境

### 自定义 history

HISTCONTROL变量定义是否删除重复命令、从历史记录中以空格开头的命令，或者同时删除这两种命令。

export HISTCONTROL=ignoredups

HISTIGNORE变量对于过滤出经常运行的基本命令特别有用，例如ls、exit、history、bg等。

export HISTIGNORE="&:ls:[bf]g:exit:history"

HISTTIMEFORMAT控制history命令输出中的日期和/或时间戳。

export HISTTIMEFORMAT='%F %T '

### 别名 alias

可以通过给命令起别名的方式，将命令的输入缩短。

例如 alias lsa=‘ls -al’

然后输入 lsa 回车，就相当于运行 ls -al了

取消别名 unalias lsa

### 持久化定制

上面的修改只是临时的，当前终端会话外就没有了，可以通过修改主目录下的.bashrc文件进行持久化，之后打开任何一个终端都会有效。可以自己查看这个文件寻找变量和别名的位置，自己按照格式添加上就可以了。