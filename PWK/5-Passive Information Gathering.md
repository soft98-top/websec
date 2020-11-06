# 5-Passive Information Gathering

## 学会记录

信息收集阶段可能产生很多的数据，所以要养成记录的习惯，然后要有一个良好的记录格式，方便后期进行检索和利用。

## 网站侦查

被动侦查阶段，在浏览目标网站时，要尽量以正常用户的角度去查看，就是简单浏览，了解网站的定位，网站涉及的内容，然后about页面，contact页面等等，查看是否有相关联系人的邮箱，社交账号之类的。

## whois

使用whois查询域名的相关信息，有时可以查看到Registry Nma，Admin Name，Tech Name和域名服务器等内容。

whois也可以根据IP地址进行反查，但是一般都是主机服务提供商的信息。

## Google Hacking

> 搜索基础：[https://github.com/K0rz3n/GoogleHacking-Page/blob/master/Basic%20knowledge.md](https://github.com/K0rz3n/GoogleHacking-Page/blob/master/Basic knowledge.md)
>
> GHDB：https://www.exploit-db.com/google-hacking-database

建议先看一下搜索基础，然后自己试一下，使用习惯了也可以大大提高检索的效率，GHDB是Google Hacking Database，上面有很逗搜索的语句，用来通过Google搜索可能存在漏洞的页面。

## 常用网站

Netcraft：https://searchdns.netcraft.com

Github：如果项目是开源的，或者有用到开源项目，可以尝试在github上查找泄露的信息和源码。

Shodan：https://www.shodan.io/

SecurityHeaders：https://securityheaders.com/

SSL Test：https://www.ssllabs.com/ssltest/

social-search（国外社交搜索）：https://www.social-searcher.com

Stack Overflow：https://stackoverflow.com/

OSINT Framework：https://osintframework.com/

## 工具

### recon-ng

recon-ng是一个基于模块的基于web的信息收集框架。侦察显示一个模块的结果到终端，但它也存储在一个数据库中。重新识别的强大功能主要在于将一个模块的结果输入到另一个模块中，从而允许我们快速扩展信息收集的范围。

`recon-ng` 运行

`marketplace search xxxx` 搜索module

`marketplace info module_path` 查看module的详细信息

`marketplace install module_path` 安装module

`modules load module_path` 加载module

在module内部，可以通过 `info` 查看详细信息，通过 `options set option_name option_value` 设置选项的值， `run` 运行， `back` 返回上一层， `show` 可以显示内容，不带任何参数，会显示可以跟随的参数，例如 `show hosts` 

### theHarvester

theHarvester ，它从多个公共数据源收集电子邮件、名称、子域名、ip和url。

```
theHarvester -d domain -b SOURCE
```

> -b SOURCE, --source SOURCE 
>
> baidu, bing, bingapi, bufferoverun, certspotter, crtsh, dnsdumpster,duckduckgo, exalead, github-code, google, hackertarget, hunter, intelx, linkedin, linkedin_links, netcraft, otx, pentesttools, projectdiscovery,qwant, rapiddns, securityTrails, spyse, sublist3r, threatcrowd,threatminer, trello, twitter, urlscan, virustotal, yahoo

### Maltego

Maltego 是一个非常强大的数据挖掘工具，提供了无尽的搜索工具和策略的组合。这个软件很大，需要一个注册的账号，然后使用软件CE版本，也就是受限的社区版本。