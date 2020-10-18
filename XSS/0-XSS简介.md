# XSS

> 原网页：https://portswigger.net/web-security/cross-site-scripting
>
> 实验室：https://portswigger.net/web-security/all-labs#cross-site-scripting
>
> XSS cheat sheet：https://portswigger.net/web-security/cross-site-scripting/cheat-sheet

## 什么是XSS？

跨站脚本攻击(也称为XSS)是一个web安全漏洞，允许攻击者破坏用户与易受攻击的应用程序的交互。它允许攻击者规避同源策略，该策略被设计用来隔离不同的网站。跨站点脚本漏洞通常允许攻击者伪装成受害用户，执行用户能够执行的任何操作，并访问用户的任何数据。如果受害用户在应用程序中拥有特权访问权，那么攻击者可能能够获得对应用程序的所有功能和数据的完全控制。

## XSS攻击如何执行？

跨站点脚本的工作方式是操纵易受攻击的web站点，使其向用户返回恶意的JavaScript。当恶意代码在受害者的浏览器中执行时，攻击者可以完全破坏他们与应用程序的交互。

## XSS的种类

> - [Reflected XSS](https://portswigger.net/web-security/cross-site-scripting#reflected-cross-site-scripting), where the malicious script comes from the current HTTP request.
> - [Stored XSS](https://portswigger.net/web-security/cross-site-scripting#stored-cross-site-scripting), where the malicious script comes from the website's database.
> - [DOM-based XSS](https://portswigger.net/web-security/cross-site-scripting#dom-based-cross-site-scripting), where the vulnerability exists in client-side code rather than server-side code.

反射型XSS，其中恶意脚本来自当前的HTTP请求。

反射式XSS是最简单的跨站点脚本。当应用程序在HTTP请求中接收数据并以不安全的方式在即时响应中包含该数据时，就会出现这种情况。

存储型XSS，恶意脚本来自网站的数据库。

当应用程序从不受信任的源接收数据并在以后的HTTP响应中以不安全的方式包含该数据时，就会出现存储的XSS(也称为持久性XSS或二级XSS)。

基于DOM的XSS，其中漏洞存在于客户端代码中，而不是服务器端代码中。

当应用程序包含一些客户端JavaScript以不安全的方式处理来自不受信任源的数据(通常是通过将数据写回DOM)时，就会出现基于DOM的XSS(也称为DOM XSS)。

## XSS攻击可以用来做什么？

> XSS攻击的实际影响通常取决于应用程序的性质、功能和数据，以及被攻击用户的状态。

冒充或伪装成受害用户。

执行用户能够执行的任何操作。

读取用户能够访问的任何数据。

捕获用户的登录凭据。

对网站进行虚拟破坏。

在网站中注入木马功能。

## 如何查找和测试XSS漏洞？

> 这里只写了手工，工具的方式自行查找，BurpSuite专业版本身也有漏扫功能。

手动测试反射和存储的XSS通常需要提交一些简单的唯一输入(例如一个简短的字母数字字符串)到应用程序的每个入口点;标识在HTTP响应中返回提交输入的每个位置;以及分别测试每个位置，以确定是否可以使用经过适当处理的输入来执行任意的JavaScript。

手工测试由URL参数引起的基于DOM的XSS涉及一个类似的过程:在参数中放置一些简单的唯一输入，使用浏览器的开发人员工具搜索DOM以获得该输入，并测试每个位置以确定它是否可用。然而，其他类型的DOM XSS更难以检测。要在非基于url的输入(如document.cookie)或非基于html的接收(如setTimeout)中发现基于dom的漏洞，没有什么可以替代检查JavaScript代码，这可能非常耗时。

## 如何防御XSS攻击？

> Content security policy (CSP) : https://portswigger.net/web-security/cross-site-scripting/content-security-policy

一般来说，有效地防止XSS漏洞可能涉及以下措施的组合:

**到达时过滤输入。**在接收到用户输入时，尽可能严格地根据预期的或有效的输入进行筛选。

**在输出中编码数据。**在HTTP响应中输出用户可控制的数据时，对输出进行编码以防止它被解释为活动内容。根据输出上下文的不同，这可能需要应用HTML、URL、JavaScript和CSS编码的组合。

**使用适当的响应标头。**为了防止HTTP响应中不包含任何HTML或JavaScript的XSS，可以使用Content-Type和X-Content-Type-Options头来确保浏览器按照您希望的方式解释响应。

**内容安全政策。**作为最后一道防线，您可以使用内容安全策略(CSP)来降低仍然存在的任何XSS漏洞的严重性。

## 可能的面试题

XSS是什么，XSS的种类，反射型和基于DOM型的区别，常见的攻击方法。

参考链接：https://my.oschina.net/u/3991187/blog/4349510