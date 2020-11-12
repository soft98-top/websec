# Clickjacking (点击劫持)

> 原网页：https://portswigger.net/web-security/clickjacking

## 什么是点击劫持？

点击劫持是一种基于界面的攻击，在这种攻击中，用户通过点击诱饵网站中的其他内容，被诱骗点击隐藏网站上可操作的内容。考虑下面的例子:

一个网络用户进入一个诱饵网站(也许这是一个电子邮件提供的链接)并点击一个按钮赢得一个奖品。在不知不觉中，他们被攻击者欺骗，按下了另一个隐藏按钮，这导致他们在另一个网站上支付了一个账户。这是一个点击劫持攻击的示例。该技术依赖于在iframe中包含一个按钮或隐藏链接的不可见的、可操作的web页面(或多个页面)的合并。iframe被覆盖在用户预期的诱骗网页内容之上。这种攻击与CSRF攻击的不同之处在于，用户需要执行一个动作，比如单击按钮，而CSRF攻击依赖于在用户不知情或不输入的情况下伪造整个请求。

## 如何构造一个基本的点击劫持攻击？

点击劫持攻击使用CSS创建和操作层。攻击者将目标网站合并为覆盖在诱饵网站上的iframe层。使用样式标签和参数的例子如下:

```
<head>
  <style>
    #target_website {
      position:relative;
      width:128px;
      height:128px;
      opacity:0.00001;
      z-index:2;
      }
    #decoy_website {
      position:absolute;
      width:300px;
      height:400px;
      z-index:1;
      }
  </style>
</head>
...
<body>
  <div id="decoy_website">
  ...decoy web content here...
  </div>
  <iframe id="target_website" src="https://vulnerable-website.com">
  </iframe>
</body>
```

目标网站iframe被放置在浏览器中，以便有一个精确的重叠的目标动作与使用适当的宽度和高度位置值的诱饵网站。无论屏幕大小、浏览器类型和平台如何，使用绝对和相对位置值来确保目标网站准确地与诱饵重叠。z-index决定了iframe和网站层的堆叠顺序。不透明度值被定义为0.0(或接近0.0)，这样iframe内容对用户是透明的。浏览器点击劫持保护可能会应用基于阈值的iframe透明检测(例如，Chrome 76版本包含此行为，但Firefox没有)。攻击者选择不透明度值，从而在不触发保护行为的情况下达到预期效果。

## 如何防御点击劫持攻击？

点击劫持是一种浏览器端行为，它的成功与否取决于浏览器的功能以及是否符合流行的web标准和最佳实践。针对clickjacking的服务器端保护是通过定义和通信组件(如iframes)使用的约束来提供的。然而，保护的实现取决于浏览器的遵从性和这些约束的执行。用于服务器端点击劫持保护的两种机制是X-Frame-Options和内容安全策略。