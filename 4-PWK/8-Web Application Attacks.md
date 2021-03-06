# 8-Web Application Attacks

## Web 应用评估方法

作为第一步，我们应该收集关于应用程序的信息。应用程序做什么?它是用什么语言写的?应用程序运行在什么服务器软件上?这些问题和其他基本问题的答案将帮助我们找到第一个(或下一个)潜在的攻击向量。

与许多渗透测试学科一样，每次尝试攻击或利用的目标都是为了增加应用程序内的权限或转移到另一个应用程序或目标。在此过程中，每个成功的攻击都可能授予对应用程序中新功能或组件的访问权。我们可能需要成功地执行几个攻击，从未经身份验证的用户帐户访问到系统上的任何类型的shell。

枚举新功能的每一步都很重要，特别是因为以前失败的攻击可能在新的上下文中成功。作为渗透测试者，我们必须继续枚举和适应，直到我们用尽所有的攻击途径或破坏系统。

## Web 应用枚举

在对web应用程序发起任何攻击之前，我们应该尝试发现正在使用的技术堆栈，它通常由以下组件组成:

程序设计语言和框架

Web服务器软件

数据库软件

服务器操作系统

- 检查 URL
- 检查页面内容
- 查看响应的头部信息
- 检查站点地图

- - robots.txt
  - sitemap.xml

- 查找管理界面

## Web 应用评估工具

自动化工具可以提高我们作为渗透测试人员的生产力，但是我们也必须理解手工开发技术，因为工具并不总是在每个情况下都可用，手工技术提供了更大的灵活性和定制性。记住，工具和自动化使我们的工作更容易。他们不为我们做这份工作。

- dirb / dirbuster

- - -r为非递归扫描，- z10为每个请求添加10毫秒延迟
  - `dirb http://www.megacorpone.com -r -z 10` 

- burpsuite

- - proxy
  - repeater
  - intruder

- chrome extension

- - Proxy SwitchyOmega
  - Cookie Editor

- Nikto

- - 最简单的选项是设置-maxtime选项，它将在指定的时间限制后停止扫描。
  - 我们的第二个选项是用-T选项调优扫描。
  - `nikto -host=http://www.megacorpone.com -maxtime=30s` 

## 利用基于Web的漏洞

### 管理界面利用

- 目录检索，定位管理界面，比如phpmyadmin
- 测试是否开启root空密码
- 分析请求数据包，利用burpsuite爆破
- 如果有遇到token的问题，可以用Grep的功能。

### XSS

[详情请点击](https://www.yuque.com/soft98/websec/gfetfa)

### 文件包含漏洞

[详情请点击](https://www.yuque.com/soft98/websec/ol6uou)

### SQL注入

[详情请点击](https://www.yuque.com/soft98/websec/kqnm7l)

## 扩展你的技能

Kali包含了几个可以创建HTTP服务器的工具。如果我们需要在任意端口上快速建立HTTP服务器，这尤其有用。

### python

我们可以在任意端口上启动HTTP服务器。通过python 2.x设置-m SimpleHTTPServer所需的模块和7331设置TCP端口:

```
python -m SimpleHTTPServer 7331
```

语法上python3.x 模块名是不同的:

```
python3 -m http.server 7331
```

这两个命令将启动一个HTTP服务器，并托管当前工作路径中的任何文件或目录。

### php

PHP包含一个内置的web服务器，可以用-S标志启动，后面跟着要使用的地址和端口:

```
php -S 0.0.0.0:8000
```

### ruby

我们还可以用Ruby“一行程序”启动HTTP服务器。该命令需要几个标志，包括-run来加载un.rb，它包含了常见Unix命令的替换，运行HTTP服务器的-e httpd，. 提供来自当前目录的内容，-p 9000设置TCP端口:

```
ruby -run -e http.d . -p 9000
```

### busybox

我们还可以使用busybox，“嵌入式Linux的瑞士军刀”，以httpd为功能来运行HTTP服务器，-f交互式运行，-p 10000运行在TCP端口10000上:

```
busybox httpd -f -p 10000
```