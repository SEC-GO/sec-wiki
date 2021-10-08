## CTF-AWD-HandBook

### **一、基线加固**

#### **1.1 修改SSH密码**
修改四台gamebox的ssh口令为约定好、便于记忆的统一强口令。
```sh
echo -e "new_password\nnew_password" | (passwd user)
echo "root:password" |chpasswd
或者使用脚本：change_ssh_pwd.py
```
注：如果在修改密码前已经被别人抢先登录，那么修改密码后不影响之前已登录的连接，除非重启机器/服务。
#### **1.2 备份源码**
```sh
cd /tmp
tar -zcvf web.tar.gz /var/www/html/ #代码的路径需要自己确认一下
```
ls 查看是否备份成功,下载到本地离线保存

也可以用scp命令：
```sh
scp -r ctf@ip:/var/www/html ip #将服务器上的/var/www/html备份到本地的ip目录，如果端口不是22，可以用-P port指定。
```
#### **1.3 修改数据库密码**
测试数据库是否能远程连接，如果不能远程连接，则一般无需更改。在远程机器上测试连接：
```sh
mysql -h ip -u root -p
```
如果数据库是能够远程连接，则应更改数据库密码，$\color{red}{并更新应用中的数据库配置}$
```sh
mysql -h 127.0.0.1 -u root -p
set password for root@127.0.0.1=password('nongfushanquan');
flush privileges;
update user set password = PASSWORD('nongfushanquan') where user = 'root';
```
#### **1.4 备份数据库**
去源代码中找数据库连接信息
```sh
grep "mysqli_connect" *.php      #php应用
find . -type f -name "*config*"  #找数据库配置文件
```
```sh
mysql -h host -u root -p
show databases;
mysqldump -h host -u root -p Test >Test0809.sql #输入密码即可
```
ls 查看是否备份成功,下载到本地离线保存，此步也可以使用navicat客户端，在界面上操作进行备份。

#### **其他（非必要）**

### **二、PHP加固、审计、应急**

#### **2.1 安装PHP WAF**
上传waf.php到远程主机/tmp/目录下：
```
scp waf.php user@remoteip:/tmp/   # 也可以使用winscp等图形化工具上传
```
install php WAF
```sh
# 上传/ctf_awd_hub/PHP/php-waf/pyset/wafset.py到远程主机
python wafset.py
```
uninstall php WAF
```sh
# 上传/ctf_awd_hub/PHP/php-waf/pyset/wafdel.py到远程主机
python wafdel.py
```
如果脚本执行错误或者服务器端不支持python2，可使用linux命令上下WAF:
```sh
# 包括子目录 install PHP WAF：
find . -path /var/www -prune -o -type f -name "*.php" -print | xargs sed -i "s/<?php/<?php\nrequire_once('\/tmp\/waf.php');/g"

# 包括子目录uninstall PHP WAF：
find . -path /var/www -prune -o -type f -name "*.php" -print | xargs sed -i "s/require_once('\/tmp\/waf.php');//g"
```
**修改web目录执行权限**：
```
cd /var/www/html
find ./ -type d -print|xargs chmod 755
```
#### **2.2 审计代码**
使用php代码审计工具进行代码审计,删除或者注释掉明显的后门PHP木马或者命令、代码执行后门。

#### **2.3 漏洞利用**
* 对审计出的明显的后门木马、命令执行、代码注入、反序列化、文件包含、文件上传漏洞快速编写利用脚本进行攻击，拿flag。
* 对waf日志监控中看到的攻击payload,进行快速编写利用脚本进行攻击，拿flag。

#### **2.4 漏洞修补**
对审计出的明显的后门木马、命令执行、代码注入、反序列化、文件包含、文件上传漏洞进行一些修补。
参照：
```php
// 过滤反序列化参数，使用时候添加黑名单类Template|Object|SoapClient|Test
function test($value) {
    $pattern = "/O(\+){0,1}:(\+){0,1}(\d+):(['\"])(Template|Object|SoapClient|Test)/is";
    if (preg_match($pattern, $value)) {
        echo "hacker" . "\n";
        $value = "";
    } else {
        echo $value . " not hack\n";
    }
    return $value;
}
```
```php
// 过滤文件后缀名，防止文件上传木马
function filterFileSufix($value) {
    $pattern = "/(^\.|.+)?\.ph(p[345]?|t|ps|tml)(\/.)?/i";
    //".+\.phps$"
    //"^\.ph(p[345]?|t|tml|ps)$"
    if (preg_match($pattern, $value)) {
        echo "hacker" . "\n";
        $value = "";
    } else {
        echo $value . " not hack\n";
    }
    return $value;
}
```
```php
// 文件包含过滤
function LFIFilter($value) {
    //首先过滤协议
    // 过滤 .. 和 /\
    // 过滤关键字
    // 过滤路径
    $pattern = "\/|\.\.\/|\.\/|etc|var|file|http|ftp|php|zlib|data|glob|phar|ssh2|rar|ogg|expect|zip|compress|filter|input";
    if (preg_match("/" . $pattern . "/is", $value)) {
        echo "hacker" . "\n";
        $value = "";
    } else {
        echo $value . " not hack\n";
    }
    return $value;
}

// 路径操纵过滤
function FilterPath($value){
    $value = str_replace(array('..','//','../','..%2f','flag'), 'x', $value);
    return $value;
}

// 命令执行过滤
function filter_0x25($str) {
    if (strpos($str, "%25") !== false) {
        $str = str_replace("%25", "%", $str);
        return filter_0x25($str);
    } else {
        return $str;
    }
}

/**
 * 过滤危险函数包括命令执行语句，SQL注入语句,严格过滤
 *
 * @param $string
 * @return string|string[]|null
 */
function hardFilter($string) {
    // url解码
    $string = urldecode(filter_0x25($string));
    $pattern = "/select|insert|update|delete|and|or|\-|#|\+|\/\*|\*|\.\.\/|\.\/|`|\\$|union|into|load_file|outfile|dumpfile|sub|hex";
    $pattern .= "|substr|mid|left|right|ascii|group_concat|concat|substring|LENGTH|BIN|OCT|ORD";
    $pattern .= "|file_put_contents|fwrite|curl|system|eval|assert|file_get_contents|base64_decode|base64_encode|phpinfo";
    $pattern .= "|passthru|exec|system|chroot|scandir|chgrp|chown|shell_exec|proc_open|proc_get_status|popen|ini_alter|ini_restore";
    $pattern .= "|`|dl|openlog|syslog|readlink|symlink|popepassthru|stream_socket_server|assert|pcntl_exec|call_user_func";
    $pattern .= "|call_user_func_array|array_map|array_filter|escapeshellcmd|hex2bin|bin2hex/is";
    $string = preg_replace($pattern, 'a', $string);
    return $string;
}

/**
 * 命令执行过滤，基本过滤
 * @param $string
 * @return string|string[]|null
 */
function easyFilter($string) {
    $string = urldecode(filter_0x25($string));
    $pattern = "/load_file\(|dumpfile\(|hex\(|substr\(|mid\(|left\(|right\(|ascii\(|group_concat\(|concat\(|substring\(";
    $pattern .= "|FIND_IN_SET\(|REPLACE\(|REPEAT\(|REVERSE\(|INSERT\(|SUBSTRING_INDEX\(|TRIM\(|PAD\(|POSITION\(|LOCATE\(|INSTR\(";
    $pattern .= "|LENGTH\(|BIN\(|OCT\(|ORD\(";
    $pattern .= "|file_put_contents\(|fwrite\(|curl\(|system\(|eval\(|assert\(|file_get_contents\(|passthru\(|exec\(|system\(";
    $pattern .= "|chroot\(|scandir\(|chgrp\(|chown\(|shell_exec\(|proc_open\(|proc_get_status\(|popen\(|ini_alter\(|ini_restore\(";
    $pattern .= "|dl\(|openlog\(|syslog\(|readlink\(|symlink\(|popepassthru\(|stream_socket_server\(|assert\(|pcntl_exec\(|phpinfo\(";
    $pattern .= "|unlink\(|fread\(|mail\(|base64_encode\(|base64_decode\(|var_dump\(";
    $pattern .= "|call_user_func_array\(|array_map\(|array_filter\(|escapeshellcmd\(|hex2bin\(|bin2hex\(/is";
    $string = preg_replace($pattern, '(', $string);
    if (preg_match($pattern, $string))
        $string = stripevil($string);
    return $string;
}
```
#### **2.5 监控与应急响应**

**文件监控**
上传文件监控脚本至web服务目录，如/var/www/html/， 修改参数，启动监控脚本。

**进程监控**
上传进程监控脚本至web服务目录，如/var/www/html/，修改参数，启动监控脚本。

**其他相关命令**

### 三、Python加固、审计、应急

#### **2.1 安装python waf**
**Flask Waf 安装步骤:**

复制hookWaf.py至flask项目根目录下

1、在根目录下新建log文件夹用于写日志文件，如果无法新建则直接修改30行和41行中的filename变量（记得在脚本监控中添加白名单）

2、修改第10行，让挂钩函数勾住flask的应用变量，可能需要拆分原有代码文件：新建一个py文件，如base.py。然后将以下创建flask应用的代码剪切入该文件：
```python
from flask import Flask
app = Flask(__name__)
```
在原有文件中引入hook之后的app：(如果原有文件已经有app = Flask(__name__)，注释掉)
```python
from hookWaf import app
```
3、配置INPUT_BLACK_LIST、BLACK_IP_LIST、WHITE_IP_LIST、SELF_IP_LIST、type_out_list、type_fake_flag

4、完成！
**Django Waf 安装步骤:**
使用说明
1. 先将RaspMiddleware.py放入工程

2. 然后在settings.py的MIDDLEWARE = []列表中加入RaspMiddleware.RaspMiddleware

3. 如果没有log文件夹，可以创建或者将日志输出路径改变

**如果WAF没有安装?**
Copy以下代码到可能出现漏洞的代码位置：
```python
#记录日志
def awdlog():
    import time
    f = open('/tmp/log.txt','a+')
    f.writelines(time.strftime('%Y-%m-%d %H:%M:%S\n', time.localtime(time.time())))
    f.writelines("{method} {url} \n".format(method=request.method,url=request.url))
    s = ''
    for d,v in dict(request.headers).items():
        s += "%s: %s\n"%(d,v)
    f.writelines(s+'\n')
    s = ''
    for d,v in dict(request.form).items():
        s += "%s=%s&"%(d,v)
    f.writelines(s.strip("&"))
    f.writelines('\n\n')
    f.close()
```
#### **2.2 审计代码**
使用PYTHON代码审计工具进行代码审计,删除或者注释掉明显的后门命令、代码执行后门。

#### **2.3 漏洞利用**
* 对审计出的明显的后门木马、命令执行、代码注入、反序列化、文件包含、文件上传漏洞快速编写利用脚本进行攻击，拿flag。
* 对waf日志监控中看到的攻击payload,进行快速编写利用脚本进行攻击，拿flag。

#### **2.3 漏洞修补**
```python
#!/usr/bin/python3
# coding=utf-8
import re
# filter ssti inject
def safe_inject1(s):
    blacklist = ['import', 'getattr', 'os', 'class', 'subclasses', 'mro', 'request', 'args', 'eval', 'if', 'for',
                 ' subprocess', 'file', 'open', 'popen', 'builtin', 'compile', 'execfile', 'from_pyfile', 'config',
                 'local', 'self', 'item', 'getitem', 'getattribute', 'func_globals', ' ', '{{', '}}',
                 'FunctionType', 'ctypes', 'globals', 'cmarshal']
    for no in blacklist:
        while True:
            if no in s:
                s = s.replace(no, 'x')
            else:
                break
    return s

# filter ssti inject
def safe_inject2(s):
    data = re.sub(
        r'(import|getattr|os|cmarshal|globals|config|ctypes|FunctionType|\{\{|\{%|class|subclasses|mro|request|args|eval|subprocess|file|open|builtin|compile|execfile|getitem|self|getattribute|func_globals)',
        "x", s, 0, re.I | re.S)
    return data

# filter ssti inject 编码绕过的情况
def filterSSTI(data=''):
    data = safe_inject1(data)
    regex1 = re.compile(r'(.*\[[\'|\"].*.[\'|\"]\].*){2,}', re.I | re.S)
    if regex1.match(data):
        return data + "hack"
    else:
        return data + "no hack"

# filter 文件下载
def filterFileDown(data=''):
    data = data.replace('..', 'x').replace('../', 'x').replace('flag', 'x')
    return data

# 过滤反序列化
def filterSerialize(data=''):
    data = safe_inject1(data)
    return data

```
#### **2.4 监控与应急响应**
**进程监控**
上传进程监控脚本至web服务目录，如/var/www/html/，修改参数，启动监控脚本。

### 四、Java审计、加固、应急

#### **2.1 安装Java RSAP**
#### **2.2 审计代码与修补漏洞**

##### 2.2.1反编译及代码审计

Java题目按应用介质形态一般可以分为jsp文件、war和可以独立运行的jar。若是war或jar，则使用jd-gui工具反编译获取源码，具体操作可以参考`jar、war包热修复`中的内容。注：将jar包直接拖进jd-gui进行反编译，依赖包也会被反编译，这样可能导致反编译时间过长，故若遇到整个jar反编译时间过长，可先对jar包进行解压缩，然后将解压得到的.class文件拖进jd-gui进行反编译，然后File->Save All Sources即可。

使用javaID优化版本(原版只扫描.java、.xml文件，不扫描.jsp，优化版本还优化了扫描规则)进行代码审计，命令：`python javaid.py -d dir`

另外，参考`jar、war包热修复`中的内容将代码（含依赖包）导入到IDE里面进行人工代码审计。



##### 2.2.2漏洞修复

不影响功能使用的情况下直接注释掉漏洞代码。

###### 1.路径穿越

```
if(name.contains("flag")||name.contains("./")||name.contains("../")||name.contains("%")) {
	return "hacker";
}
```

###### 2.命令注入

```
private static final Pattern FILTER_PATTERN = Pattern.compile("^[a-zA-Z0-9_/\\.-]+$");
if (!FILTER_PATTERN.matcher(sql).matches()) {
   return "hacker";
}
```

###### 3.XXE

参考`CheatSheetSeries`中的`XML_External_Entity_Prevention_Cheat_Sheet`

###### 4.SpEL表达式注入

将StandardEvaluationContext替代为SimpleEvaluationContext，由于StandardEvaluationContext权限过大，可以执行任意代码，会被恶意用户利用。SimpleEvaluationContext的权限则小的多，只支持一些map结构，通用的jang.lang.Runtime,java.lang.ProcessBuilder都已经不再支持。

```
参考1:
A a=new A("ruilin");
ExpressionParser parser = new SpelExpressionParser();
EvaluationContext context = SimpleEvaluationContext.forReadOnlyDataBinding().withRootObject(a).build();
String name = (String) exp.getValue(context);
System.out.println(name);

参考2:
String expression = request.getParameter("message");
ExpressionParser parser = new SpelExpressionParser();
Expression exp = parser.parseExpression(expression);
StandardEvaluationContext context = SimpleEvaluationContext.forReadOnlyDataBinding().withRootObject().build();
String message = exp.getValue(context, String.class);
exp.setValue(context, "Hello");
```

###### 5.反序列化漏洞

升级第三方组件



##### Java重打包（jar包修复）

###### 1.GUI界面操作

用winwar等解压缩软件打开war或jar，找到待更新的文件，直接将新的修复好的同名文件拖拽进去替换即可。

###### 2.命令操作

0.先对原始应用包进行备份。

1.查找修复的类文件的路径，比如修复了SecurityConfig.java

```
jar vtf easybank.jar|grep SecurityConfig
  6250 Wed Aug 05 22:03:08 CST 2020 BOOT-INF/classes/com/hendisantika/onlinebanking/config/SecurityConfig.class
```

2.解压被修复的文件对应的class

```
jar xvf easybank.jar BOOT-INF/classes/com/hendisantika/onlinebanking/config/SecurityConfig.class
```

3.用修复好的SecurityConfig.class覆盖上一步解压出来的原始文件

4.更新jar包

```
 jar uvf easybank.jar BOOT-INF/classes/com/hendisantika/onlinebanking/config/SecurityConfig.class
正在添加: BOOT-INF/classes/com/hendisantika/onlinebanking/config/SecurityConfig.class(输入 = 6217) (输出 = 2023)(压缩了 67%)
```

命令操作也可以参考`jar、war包热修复`

#### **2.3 漏洞利用**
#### **2.4 监控与应急响应**

