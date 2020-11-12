# 4-Bash Scripting

## 简介

Bash脚本是一个纯文本文件，其中包含一系列命令，执行这些命令时就像它们是在终端提示符处输入的一样。一般来说，Bash脚本有一个可选的扩展名.sh(为了便于识别)，以 `#!/bin/bash` ，在执行之前必须设置可执行权限。

```
#! /bin/bash
# Hello World Bash Script
echo "Hello world!"
```

其中 `#!` 通常被称为shebang，被Bash解释器忽略。第二部分 `/bin/bash` 是解释器的绝对路径，它用于运行脚本。这就是为什么这是一个“Bash脚本”，而不是另一种类型的shell脚本，如“C shell脚本”。

`#` 用来添加注释，所有跟在后面的文本会被忽略。

`echo "Hello World !"` 使用echo Linux命令实用程序将给定的字符串打印到终端，在本例中是“Hello World!”

## 变量

### 基础

定义变量 `name=value` ，中间不能有空格，定义好的变量用 `$name` 取值。

如果是一句话，比如把 Hello World！赋值给greeting，需要加单引号或双引号， `greeting='Hello world！'` 。请注意，这里加单引号和双引号是有区别的。Bash以不同的方式处理单引号和双引号。当遇到单引号时，Bash按字面意思解释每个封闭的字符。当用双引号括起来时，除"$"、" ' "和"\"外的所有字符都按字面意义进行查看，这意味着变量将在初始替换中展开，传递所括起来的文本。例如：

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1604382875754-4f9f551e-248e-4b0e-867b-ddb1d9c7503a.png)

我们还可以将变量的值设置为命令或程序的结果。这被称为命令替换，它允许我们获取命令或程序的输出(通常会打印到屏幕上)，并将其保存为变量的值。为此，将变量名放在括号“()”中，前面加上一个“$”字符: `user=$(whoami)` ，或者用反撇号，不过这种方法已经不推荐用了： `user=`whoami`` 

### 参数

在bash脚本里面是可以读取传进来的参数的，比如 `$1` 就是第一个参数，一般传参就是执行脚本时后面空格输入参数。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1604383345771-cf17b9c4-9d2b-4eaf-a34f-ffe264fcde21.png)

### 读取用户输入

通过使用 `read` 读取用户实时交互的输入，比如 `read answer` 就会要求用户输入，然后将输入的内容存放在变量answer中。

使用read时也可以带一些选项，比如提水信息等， `-p` 增加提示信息， `-s` 静默输入，就是不显示输入过程，适用于输入密码。比如： `read -sp "请输入密码："` 

### if，else，elif语句

条件语句允许我们根据不同的条件执行不同的动作。最常见的条件Bash语句包括if、else和elif。

```
if [ <some test> ] 
then 
    <perform an action> 
elif [ <some test> ]
then
    <perform an action>
else
    <perform an action>
fi
```

在这个列表中，如果“some test”的值为true，那么脚本将“执行一个动作”，或者执行在这个动作和fi之间的任何命令。

```
#!/bin/bash
# if statement example
# 输入的年龄小于16就会提示

read -p "What is your age: " age
if [ $age -lt 16 ]
then
        echo "You might need parental permission to take this course!"
fi
```

if后面的[] 中间引起的判断语句，也可以在语句前面加个test，然后把 []去掉，下面是一些测试的语法。

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1604385031053-728008c4-990a-465b-87d3-a5709eb18034.png)

## 布尔逻辑运算

AND(&&)和OR(||)布尔逻辑操作符有些神秘，因为Bash以各种方式使用它们。

一种常见的用法是在命令列表中，命令列表是由操作符控制其流的命令链。“|”(管道)符号是命令列表中常用的操作符，它将一个命令的输出传递给另一个命令的输入。类似地，布尔逻辑运算符根据前一个命令是否成功(或返回True或0)或失败(返回False或非零)执行命令。

例如： `grep $user2 /etc/passwd && echo "$user2 found!" || echo "$user2 not found !"` 

## 循环

### for循环

for循环非常实用，在Bash一行程序中工作得非常好。这种类型的循环用于对列表中的每个项执行一组给定的命令。让我们简单看看它的一般语法:

```
for var-name in <list> 
do 
    <action to perform> 
done
```

让我们看一个更实际的例子，它将快速打印10.211.55.0/24子网的前10个IP地址:

```
for ip in $(seq 1 10); do echo 10.211.55.$ip; done
for ip in {1..10}; do echo 10.211.55.$ip; done
```

### while循环

While循环也非常常见，当表达式为真时执行代码。While循环有一个简单的格式，像if，使用方括号([])进行测试:

```
while [ <some test> ] 
do 
    <perform an action> 
done
```

while循环打印前十个IP：

```
#!/bin/bash
# while loop example

counter=1
while [ $counter -le 10 ]
do
        echo "10.211.5.$counter"
        ((counter++))
done
```

### 函数

在Bash脚本方面，我们可以将函数看作脚本中的脚本，当需要在脚本中多次执行相同的代码时，这非常有用。我们不需要一遍又一遍地重写相同的代码块，我们只需将它作为一个函数编写一次，然后根据需要调用该函数。

两种定义方式，结果一样，看个人的喜好自行选择。调用函数直接写函数名就可以，函数可以接收传参，但是不需要预定义。

```
function function_name {
    commands..
}
function_name() {
    commands..
}
```

除了向Bash函数传递参数外，我们当然还可以从Bash函数返回值。Bash函数实际上不允许按传统意义返回任意值。相反，Bash函数可以返回退出状态(为成功返回零，为失败返回非零)或其他任意值，然后我们可以从全局变量 `$?` 中读取。另外我们可以在函数内部设置一个全局变量，或者使用命令替换来模拟传统的返回。

```
#!/bin/bash
# function return value example

return_me() {
        echo "Oh hello there, I'm returning a random value!"
        return $RANDOM
}

return_me
echo "The previous function returned a value of $?"
```

### 变量作用域

全局变量就是正常定义的 `name=value` ，可以在所有范围内读取到，局部变量用 `local name=value` 在函数内部定义，局部变量和全局变量重名时，函数内部先读取和修改局部变量，修改局部变量不影响全局变量。

## 实用的例子

### Example1 - 收集页面中子域名

先下载网址的主页：`wget www.baidu.com`

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1604402158503-61533210-0548-4498-9847-60514cceca5c.png)

利用正则表达式截取子域名到list.txt， `grep -o '[^/]\.baidu\.com' index.html | sort -u > list.txt` 

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1604402283275-7599424c-2f16-4bed-b3ed-114c9e1903fe.png)

 用for循环遍历子域名，然后用host去查询IP地址， `for url in $(cat list.txt); do host $url; done` 

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1604402604904-50f09908-3540-4ce8-81d5-2969cd315dd0.png)

因为只是想要地址，然后发现成功的是有 `has address` 的字样，然后处理一下，`for url in $(cat list.txt); do host $url; done | grep "has address" | awk '{print $4}'`

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1604402753849-e193214b-2a26-4289-b81c-c92f0c2a3842.png)

### Example2 - 下载exploit-db的exploit

kali自带命令 `searchsploit` 可以去搜索exploit-db， `-w` 返回URL， `-t` 是搜索标题。

例如： `searchsploit afd windows -w -t` 

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1604404977086-45878802-9165-4ee2-87e8-da25b82176cd.png)

然后处理一下，将URL筛选出来： `searchsploit afd windows -w -t | grep http | cut -f 2 -d "|"` 

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1604405149765-ad8554b4-9e83-406f-9098-082d129196ee.png)

但是实际的下载地址其实是将URL中的exploits替换成raw，所以我们就需要用 `sed` 替换一下，然后遍历用 `wget` 下载。

```
for e in $(searchsploit afd windows -w -t | grep http | cut -f 2 -d "|"); do exp_name=$(echo $e | cut -d "/" -f 5) && url=$(echo $e | sed 's/exploits/raw/') && wget -q --no-check-certificate $url -O $exp_name; done
```

最后做了一个综合的脚本，脚本运行之前用 `chmod +x` 加上执行权限，然后用 `./shellname.sh` 运行。

```
#! /bin/bash
# Bash script to search for a given exploit and download all matches

if test -z "$1"
then
        read -p "please input what you want to search: " keyword
else
        keyword="$1"
fi
(searchsploit $keyword -w -t)
read -p "Do you wanna download? Y/N: " flag
if test $flag = 'Y' ||test $flag = 'y'
then
        for e in $(searchsploit $keyword -w -t | grep http | cut -f 2 -d "|")
        do
                exp_name=$(echo $e | cut -d "/" -f 5)
                url=$(echo $e | sed 's/exploits/raw/')
                wget -q --no-check-certificate $url -O $exp_name
        done
fi
```

### Example3 - 扫描C段，并查看相应的访问界面

nmap扫描C段： `sudo nmap -A -p80 --open 10.211.55.0/24 -oG nmap_scan_10.211.55.1-254` 

筛选出指定的行然后去除首行nmap标识，并用awk把IP地址拿出来： `cat nmap-scan_10.211.5.1-254 | grep 80 | grep -v "Nmap" | awk '{print $2}'` 

用for循环遍历，然后用cutycapt进行访问并渲染页面： `for ip in $(cat nmap-scan_10.11.1.1-254 | grep 80 | grep -v "Nmap" | awk '{print $2}'); do cutycapt --url=$ip --out=$ip.png;done` 

图片生成完之后，有一个脚本可以将这些图片合并到一个网页中。

```
#!/bin/bash # Bash script to examine the scan results through HTML.

echo "<HTML><BODY><BR>" > web.html

ls -1 *.png | awk -F : '{ print $1":\n<BR><IMG SRC=\""$1""$2"\" width=600><BR>"}' >> w eb.html

echo "</BODY></HTML>" >> web.html
```

