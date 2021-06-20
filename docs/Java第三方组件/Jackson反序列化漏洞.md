# Jackson漏洞原理与检测、利用方式研究
# Jackson简介
前面分析了两个关于 fastjson 的漏洞，这篇文章再提一嘴 Jackson。
实际上这两个JSON处理类库的多数漏洞是可以通用的，原理也就是通过反射实例化对象，在调用构造函数或调用get/set方法时触发敏感操作。Jackson框架被发现存在一个反序列化代码执行漏洞。该漏洞存在于Jackson框架下的enableDefaultTyping方法，通过该漏洞，攻击者可以远程在服务器主机上越权执行任意代码，从而取得该网站服务器的控制权。
```java
ObjectMapper mapper = new ObjectMapper();
mapper.enableDefaultTyping();
mapper.readValue(jsonString, A.class);
```
DefaultTyping的几种模式：
```java
/**
    * This value means that only properties that have
    * {@link java.lang.Object} as declared type (including
    * generic types without explicit type) will use default
    * typing.
*/
JAVA_LANG_OBJECT: 只有Object类型属性，才能反序列化为任何实例。
/**
    * Value that means that default typing will be used for
    * properties with declared type of {@link java.lang.Object}
    * or an abstract type (abstract class or interface).
    * Note that this does <b>not</b> include array types.
    *<p>
    * Since 2.4, this does NOT apply to {@link TreeNode} and its subtypes.
*/
OBJECT_AND_NON_CONCRETE: 包含上述 JAVA_LANG_OBJECT 的特性，并且对于接口类型定义的属性，可以反序列化为任意实现类实例，不指定的时候默认使用该类型。
/**
    * Value that means that default typing will be used for
    * all types covered by {@link #OBJECT_AND_NON_CONCRETE}
    * plus all array types for them.
    *<p>
    * Since 2.4, this does NOT apply to {@link TreeNode} and its subtypes.
*/
 NON_CONCRETE_AND_ARRAYS: 包含上述 JAVA_LANG_OBJECT 和 OBJECT_AND_NON_CONCRETE 的特性，增加了数组支持
/**
    * Value that means that default typing will be used for
    * all non-final types, with exception of small number of
    * "natural" types (String, Boolean, Integer, Double), which
    * can be correctly inferred from JSON; as well as for
    * all arrays of non-final types.
    *<p>
    * Since 2.4, this does NOT apply to {@link TreeNode} and its subtypes.
*/
 NON_FINAL: 包含上述所有特性，除了final定义的属性不能反序列化，其他都可以
```
# 参考
https://blog.csdn.net/qq_34101364/article/details/111996656

http://pirogue.org/2018/01/12/jackson-databind-rce/

https://b1ue.cn/archives/189.html

http://blog.nsfocus.net/jackson-framework-java-vulnerability-analysis/

https://xz.aliyun.com/t/8012

https://xz.aliyun.com/t/9331