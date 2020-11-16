# Sqlmap

## 参数详解

[sqlmap-cheatsheet-1.0-SDB.pdf](https://www.yuque.com/office/yuque/0/2020/pdf/2398693/1605532760682-948d73de-8e2b-498b-bf0d-c9aec4446525.pdf)

### 目标 :( 必须提供这些选项中的至少一个)

-u URL 目标URL 

-d DIRECT 直接连接到数据库

-m FILE 文件中的目标 

-l LOGFILE 从Burp/WebScarab解析

-r FILE 加载HTTP请求文件 

-g GDORK 谷歌dork作为目标

### 请求 :( 指定如何连接到目标URL)

--data=DATA 通过POST发送的数据字符串

--param-del=PDEL 用于拆分参数值的字符

--cookie=COOKIE HTTP Cookie头

--cookie-del=CDEL 用于拆分cookie值的字符

--load-cookies=L.. 包含Netscape/wget格式的cookie的文件

--drop-set-cookie 从响应中忽略Set-Cookie头

--user-agent=AGENT 指定用户头信息

--random-agent 随机生成头信息

--host=HOST

--referer=REFERER

--headers=HEADERS

--auth-type=AUTH.. Basic、摘要、NTLM或PKI

--auth-cred=AUTH.. 名称: 密码

--auth-private=A.. PEM私钥文件

--proxy=PROXY

--proxy-cred=PRO.. 名称: 密码

--proxy-file=PRO.. 文件列表 

--ignore-proxy 忽略系统设置

--tor 

--tor-port=TPORT

--tor-type=TYPE HTTP (dflt), SOCKS4, SOCKS5

--check-tor 检查Tor是否使用正确

--delay=DELAY 每个HTTP请求之间的延迟 (以秒为单位)

--timeout=TIMEOUT 超时前等待的秒数 (默认为30)

--retries=RETRIES 超时前等待的秒数 (默认为30)

--randomize=RPARAM 随机改变给定参数的值

--safe-url=SAFURL 测试期间经常访问的URL地址

--safe-freq=SAFREQ 测试两次访问给定安全URL之间的请求

--skip-urlencode 跳过有效负载数据的URL编码

--force-ssl 强制使用SSL/HTTPS

--hpp 使用HTTP参数污染

--eval=EVALCODE 在请求之前评估提供的Python代码 (例如 “import hashlib;id2=hashlib.md5(id).hexdigest()”)

### 优化:

-o 打开所有优化开关

--predict-output 预测常见查询输出

--keep-alive 使用持久HTTP连接

--null-connection 检索没有实际HTTP响应正文的页面长度

--threads=THREADS 并发HTTP请求的最大数量 (默认值为1)

### 注入:

-p TESTPARAMETER 可测试参数

--skip=SKIP 跳过给定参数的测试

--dbms=DBMS 强制后端DBMS为该值

--dbms-cred=DBMS.. DBMS身份验证凭据 (用户: 密码)

--os=OS 强制后端DBMS OS为该值

--invalid-bignum 使用大数字使值无效

--invalid-logical/--invalid-string 使用逻辑/随机来使值无效

--no-cast/--no-escape 关闭有效载荷铸造/逃逸

--prefix=PREFIX/--suffix=SUFFIX 注入有效载荷前缀/后缀字符串

--tamper=TAMPER 使用给定脚本篡改注入数据

### 检测 :( 用于定制/改进检测阶段)

--level=LEVEL 要执行的测试级别 (1-5，默认值1)

--risk=RISK 执行测试的风险 (0-3，默认值1)

--string=STRING/--not-string=NOT.. 当查询计算为True/False时匹配

--regexp=REGEXP 当查询计算为True时匹配的正则表达式

--code=CODE 当查询计算为True时要匹配的HTTP代码

--text-only/--titles 仅基于文本内容/标题比较pag

### 技术 :( 用于调整特定SQL注入的测试)

--technique=TECH 要使用的SQL注入技术 (默认为 “BEUSTQ”)

--time-sec=TIMESEC 延迟DBMS响应的秒数 (默认为5)

--union-cols=UCOLS 要测试UNION查询SQL注入的列范围

--union-char=UCHAR 用于强制执行列数的字符

--union-from=UFROM 从UNION query SQL注入的一部分中使用的表

--dns-domain=DNS.. 用于DNS过滤攻击的域名

--union-from=UFROM 从UNION query SQL注入的一部分中使用的表

--dns-domain=DNS.. 用于DNS过滤攻击的域名

--second-order=S.. 搜索结果页面URL以获取二阶响应

### 枚举 :( 枚举包含的后端数据库、结构和数据)

-a, --all 检索所有内容

-b 检索banner

--is-dba 检查用户是否为DBA

--current-user/--current-db/--hostname 检索DBMS当前用户/数据库/主机名

--users/--passwords 枚举DBMS用户/用户密码散列

--privileges/--roles 枚举DBMS用户特权/角色

--dbs/--tables/--columns/--schema 枚举DBMS 数据库/表/列/schema

--count 检索表的条目数

--search 搜索列，表/数据库名称

--dump-all 转储所有DBMS 数据库表条目

--dump 转储DBMS 数据库表条目

-U USER 要枚举的DBMS用户

--exclude-sysdbs 排除系统数据库

--comments 检索DBMS注释

-X EXCLUDECOL 表列设置为不枚举

-D DB / -T TBL / -C COL 要枚举的DBMS数据库 /表 / 列

--where=DUMPWHERE 在表转储时使用WHERE条件

--start=LIMITSTART/--stop=LIMITSTOP 要检索的第一个/最后一个查询输出条目

--first=FIRSTCHAR/--last=LASTCHAR 要检索的第一个/最后一个查询输出的单词字符

--sql-file=SQLFILE 从给定文件执行SQL语句

--sql-shell 交互式SQL shell提示

### 常规:

-s SESSIONFILE 从 .sqlite 文件加载会话

-t TRAFFICFILE 记录所有HTTP流量

--batch 永远不要要求输入

--eta 显示每个eta

--save 将选项保存到配置INI文件

--update 更新sqlmap

--charset=CHARSET 强制字符编码用于数据检索

--crawl=CRAWLDEPTH 从目标URL开始爬网网站

--csv-del=CSVDEL CSV输出中使用的分隔字符 (默认 “，”)

--dump-format=DU.. 转储数据的格式 (CSV (默认) 、HTML或SQLITE)

--flush-session 刷新当前目标的会话文件

--forms 在目标URL上解析和测试表单

--fresh-queries 忽略存储在会话文件中的查询结果

--hex 使用DBMS十六进制函数进行数据检索

--output-dir=ODIR 自定义输出目录路径

--parse-errors 解析并显示来自响应的DBMS错误消息

--pivot-column=P.. 主列名称

--scope=SCOPE 从提供的代理日志筛选目标的正则表达式

--test-filter=TE.. 按有效载荷和/或标题选择测试 (例如行)

### 指纹:

-f, --fingerprint 执行广泛的DBMS版本指纹识别

### 蛮力:

--common-tables/--common-columns 检查常见表/列

### 用户定义的函数注入:

--udf-inject 注入自定义函数

--shared-lib=SHLIB 共享库的本地路径

### 文件系统访问:

--file-read=RFILE/--file-write=WFILE 在DBMS文件系统上读取/写入本地文件

--file-dest=DFILE 要写入的后端DBMS绝对文件路径

### 操作系统访问:

--os-cmd=OSCMD 执行操作系统命令

--os-shell 交互式操作系统shell

--os-pwn OOB shell、meterpreter或VNC

--os-smbrelay 一键提示OOB shell、meterpreter或VNC

--os-bof 存储过程缓冲区溢出利用

--priv-esc 数据库进程用户权限提升

--msf-path=MSFPATH/--tmp-path=TMPPATH 本地Metasploit/远程tmp路径

### Windows注册表访问:

--reg-read/--reg-add/--reg-del 读/写/删除win注册表项值

--reg-key=REGKEY win registry key

--reg-value=REGVAL win reg key value

--reg-data=REGDATA win reg key data 

--reg-type=REGTYPE win reg key value type

### 其他:

-z MNEMONICS 使用短助记符 (e.g. "flu,bat,ban,tec=EU")

--alert=ALERT 找到SQL注入时，运行主机操作系统命令

--answers=ANSWERS 设置问题答案 (e.g. "quit=N,follow=N")

--check-waf/--identify-waf WAF/IPS/IDS保护

--cleanup 从特定于sqlmap的UDF和表清理DBMS

--dependencies 检查缺少 (非核心) sqlmap依赖项

--gpage=GOOGLEPAGE 使用指定页码的Google dork结果

--mobile 通过HTTP用户代理头模仿智能手机

--page-rank 显示Google dork结果的页面排名 (PR)

--purge-output 安全地从输出目录中删除所有内容

--smart 只有在积极启发式的情况下才进行测试

--disable-coloring 

--beep 如果找到sql注入。

--wizard 面向初学者的向导界面