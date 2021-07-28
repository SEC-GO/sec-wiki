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

````__getattribute__```: 实例、类、函数都具有的__getattribute__魔术方法。事实上，在实例化的对象进行操作的时候（形如：a.xxx/a.xxx()），都会自动去调用__getattribute__方法。因此我们同样可以直接通过这个方法来获取到实例、类、函数的属性。

## import相关的基础


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

【Escaping the Python Sandbox】https://zolmeister.com/2013/05/escaping-python-sandbox.html<br>
【Sandbox Escape with Python】https://prog.world/sandbox-escape-with-python/<br>
【】http://www.secwk.com/2019/10/17/11283/<br>
【】https://www.cnblogs.com/tr1ple/p/9415641.html<br>
【】https://www.freebuf.com/articles/system/203208.html<br>