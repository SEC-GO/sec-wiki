# **PHP代码审计备忘**
## PHP弱类型问题
### int、String的转换
```php
var_dump(intval(4))//4
var_dump(intval(‘1asd’))//1
var_dump(intval(‘asd1’))//0
intval（）函数在转换字符串的时候即使碰到不能转换的字符串的时候它也不会报错，而是返回0
```
### 比较操作符
在编程中类型转换是不可避免的一个事情，比如说网络编程中get方法或者post方法传入一个需要转换成int的值，再比如说变量间进行比较的时候，需要将变量进行转换，鉴于php是自动进行类型转换，所以会引发很多意想不到的问题。
**“= =”与“= = =”比较操作符问题**
php有两种比较方式,一种是“= =”一种是“= = =”这两种都可以比较两个数字的大小，但是有很明显的区别。
* “= =”：会把两端变量类型转换成相同的，在进行比较。
* “= = =”：会先判断两端变量类型是否相同，在进行比较。<br>

这里明确说明，在两个相等的符号中，一个字符串与一个数字相比较时，字符串会转换成数值。
注意：在两个相等的符号中，一个字符串与一个数字相比较时，字符串会转换成数值
```php
<?php
         var_dump("name"==0);  //true
         var_dump("1name"==1); //true
         var_dump("name1"==1) //false
         var_dump("name1"==0) //true
         var_dump("0e123456"=="0e4456789"); //true
 ?>
 ```
* hash比较操作符问题
"0e123456"=="0e4456789"，当出现xex模式的时候代表科学计数法，2个数的值都是0因而就相等了<br>
```php
以下值在md5加密后以0E开头：
QNKCDZO
240610708
s878926199a
s155964671a
s214587387a
s214587387a
以下值在sha1加密后以0E开头：
sha1(‘aaroZmOk’)
sha1(‘aaK1STfY’)
sha1(‘aaO8zKZF’)
sha1(‘aa3OFF9m’)
```
* 十六进制转换问题<br>
"0x1e240"=="123456" //true<br>
"0x1e240"==123456 //true<br>
"0x1e240"=="1e240"//false<br>
php在接受一个带0x的字符串的时候，会自动把这行字符串解析成十进制的再进行比较，0x1e240解析成十进制就是123456，并且与字符串类型的123456和int型的123456都相同。
布尔值转换问题
```php
<?php
      If( true = “name”){
          echo “success”;
}
```
布尔值可以和任何字符串相等。


### 总结
* 1、字符串和数字比较，字符串会被转换成数字。<br>
* 2、混合字符串转换成数字，看字符串的第一个。<br>
* 3、字符串开头以xex开头，x代表数字。会被转换成科学计数法（注意一定要是0e/d+的模式）。但是也有例外如：-1.3e3转换为浮点数是-1300。<br>
* 4、0x开头的字符串会先解析成十六进制再进行比较<br>
* 5、布尔值跟任意字符串都弱类型相等<br>
### strcmp绕过
```php
int strcmp ( string str1, string str1, string str2 ),
需要给strcmp()传递2个string类型的参数。如果str1小于str2,返回-1，相等返回0，否则返回1
<?php
     $password="***************
     if(isset($_POST['password'])){
        if (strcmp($_POST['password'], $password) == 0) {
            echo "Right!!!login success";n
            exit();
        } else {
            echo "Wrong password..";
        }
?>
我们传入password[]=xxx ，绕过成功。原理是因为函数接受到了不符合的类型，将发生错误，函数返回值为0，所以判断相等。
```
### 利用数组绕过数值比较
```php
$AA[]='admin';
if($AA < 9999999999){
    echo "hello world";
}
else if ((string)$AA>0) {
    echo 'A_A,too big';
}
if ((string)$AA == 0) {
    echo "ddddddddddd";
}
（1）无论你的数字多大，对于数值而言总是比数组小
（2）强制转化为字符串在与数字比较的判断，这就是平常操作很多的弱类型了，直接让参数等于admin就可以了，因为“admin”== 0 ，结果是true，直接等于0绕过即可, 即(string)$AA == 0成立
```
### is_numeric()漏洞
```php
php 5.x 版本中 is_numeric 的缺陷 (php7.0 已经修复了 ), 它认为 0x…. 是整数
比如：if(!is_numeric($page)){
		Die("sssssssssssssss   hacker hacker ");
	 }
如果是整数然后执行：$sql="update page set num=$page"; $res=mysql_my_query($sql);
可以将SQL注入语句转换为16进制
a='1 union all select flag,flag,flag,flag from flags' binascii.hexlify(a) ——> 3120756e696f6e20616c6c2073656c65637420666c61…….
传入page = 0x3120756…….即可绕过整数判断
```