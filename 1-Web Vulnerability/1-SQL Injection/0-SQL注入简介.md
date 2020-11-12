# SQL injection

> 原网页：https://portswigger.net/web-security/sql-injection
>
> SQli实验室：https://portswigger.net/web-security/all-labs#sql-injection
>
> SQL注入常用语句：https://portswigger.net/web-security/sql-injection/cheat-sheet

## 什么是SQL注入？

SQL注入是一个web安全漏洞，它允许攻击者干扰应用程序对其数据库的查询。它通常允许攻击者查看他们通常无法检索的数据。这可能包括属于其他用户的数据，或者应用程序本身能够访问的任何其他数据。在许多情况下，攻击者可以修改或删除这些数据，从而导致对应用程序的内容或行为的持久更改。

## 一次成功的SQL注入攻击能造成什么影响？

一次成功的SQL注入攻击可能导致对敏感数据的未授权访问，例如密码、信用卡详细信息或个人用户信息。近年来，许多引人注目的数据泄露事件都是由SQL注入攻击造成的，这些攻击导致了声誉受损和监管罚款。在某些情况下，攻击者可以获得进入组织系统的持久后门，从而导致长期的破坏，并在很长一段时间内不被发现。

## 常见的SQL注入

Retrieving hidden data - 检索隐藏的数据

Subverting application logic - 颠倒程序逻辑

Retrieving data from other database tables - 从其它数据库表中检索数据

- - UNION attacks

Examining the database - 检查数据库

Blind SQL injection vulnerabilities - SQL盲注漏洞

## 如何发现SQL注入漏洞

通过对应用程序中的每个入口点使用一组系统测试，可以手动检测SQL注入。这通常包括:

- - Submitting the single quote character `'` and looking for errors or other anomalies.
  - Submitting some SQL-specific syntax that evaluates to the base (original) value of the entry point, and to a different value, and looking for systematic differences in the resulting application responses.
  - Submitting Boolean conditions such as `OR 1=1` and `OR 1=2` , and looking for differences in the application's responses.
  - Submitting payloads designed to trigger time delays when executed within an SQL query, and looking for differences in the time taken to respond.
  - Submitting OAST payloads designed to trigger an out-of-band network interaction when executed within an SQL query, and monitoring for any resulting interactions.

在查询的不同部分的SQL注入

- - In `UPDATE` statements, within the updated values or the `WHERE` clause.
  - In `INSERT` statements, within the inserted values.
  - In `SELECT` statements, within the table or column name.
  - In `SELECT` statements, within the `ORDER BY` clause.

## 二阶SQL注入

当应用程序从HTTP请求获取用户输入，并在处理该请求的过程中以不安全的方式将输入合并到SQL查询中时，就会出现一级SQL注入。

在二阶SQL注入(也称为存储SQL注入)中，应用程序从HTTP请求获取用户输入并存储它以供将来使用。这通常是通过将输入放入数据库来实现的，但是在存储数据的地方不会出现漏洞。稍后，在处理不同的HTTP请求时，应用程序检索存储的数据并以不安全的方式将其合并到SQL查询中。

二阶SQL注入通常出现在这样的情况下:开发人员知道SQL注入漏洞，因此可以安全地处理数据库中输入的初始位置。当数据稍后被处理时，它被认为是安全的，因为它之前被安全地放入了数据库。此时，数据的处理是不安全的，因为开发人员错误地认为它是可信的。

## 特定数据库的元素

公共数据库之间也有许多不同之处。这意味着某些用于检测和利用SQL注入的技术在不同平台上的工作方式不同。例如:

- - Syntax for string concatenation. 字符串连接的语法
  - Comments. 评论/解释
  - Batched (or stacked) queries. 批处理（或堆叠）查询
  - Platform-specific APIs. 特定于平台的API
  - Error messages. 错误消息

## 如何阻止SQL注入

通过在查询中使用参数化查询(也称为prepared statements)而不是字符串连接，可以防止大多数的SQL注入。

参数化查询可用于不受信任的输入作为查询中的数据出现的任何情况，包括where子句和INSERT或UPDATE语句中的值。它们不能用于处理查询的其他部分中的不可信输入，例如表或列名，或ORDER BY子句。将不受信任的数据放入这些查询部分的应用程序功能需要采用不同的方法，比如白名单允许的输入值，或者使用不同的逻辑来交付所需的行为。

要使参数化查询有效地防止SQL注入，查询中使用的字符串必须始终是硬编码的常量，并且绝不能包含来自任何来源的任何变量数据。不要试图逐个判断数据项是否可信，并继续在查询中使用被认为安全的字符串连接。人们很容易在数据的可能来源方面犯错误。

## 可能的面试题

谈一下对SQL注入的理解，产生的原因、SQL注入的分类、防御措施。

SQL注入介绍及分类解读：http://baijiahao.baidu.com/s?id=1653173591310148806