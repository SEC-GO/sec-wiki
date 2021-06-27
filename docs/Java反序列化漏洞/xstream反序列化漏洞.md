# **XStream Basics**
在描述攻击之前，让我们回顾一下XStream的一些基础知识。XStream是一个XML序列化库，可以在Java类型和XML之间进行转换。考虑一个简单的Person类：
```java
public class Person {
    @XStreamAlias("firstName") //别名注解
    private String firstName;
    @XStreamAlias("lastName")
    private String lastName;
    @XStreamAlias("address")
    private Address address;
    // 省略get和set函数
}
class Address{
    @XStreamAlias("国")
    private String country;
    @XStreamAlias("省")
    private String province;
    @XStreamAlias("市")
    private String city;
    // 省略get和set函数
}
```
**由Object生成XML：**
```java
Person person = new Person();
person.setFirstName("jack");
person.setLastName("Ma");
Address address = new Address();
address.setCountry("China");
address.setProvince("ZheJiang");
address.setCity("HangZhou");
person.setAddress(address);
XStream xstream=new XStream();
//XStream xstream=new XStream(new DomDriver()); //直接用jaxp dom来解释
//XStream xstream=new XStream(new DomDriver("utf-8")); //指定编码解析器,直接用jaxp dom来解释
////如果没有这句，xml中的根元素会是<包.类名>；或者说：注解根本就没生效，所以的元素名就是类的属性
xstream.processAnnotations(person.getClass()); //通过注解方式的，一定要有这句话
//将某一个类的属性，作为xml节点的属性，而不是子节点
xstream.useAttributeFor(Address.class, "country");
String xml = xstream.toXML(person);
System.out.println(xml);
-----------------------------------------输出---------------------------------------------
<person>
  <firstName>jack</firstName>
  <lastName>Ma</lastName>
  <address 国="China">
    <省>ZheJiang</省>
    <市>HangZhou</市>
  </address>
</person>
```
在这两种情况下，XStream都使用Java反射将Person类型转换为XML或从XML转换为Person类型。攻击发生在读取XML期间。在读取XML时，XStream使用反射实例化Java类。

**由XML生成Object：**
```java
 String testXMl = "<person>\n" +
                "  <firstName>jack</firstName>\n" +
                "  <lastName>Ma</lastName>\n" +
                "  <address 国=\"China\">\n" +
                "    <省>ZheJiang</省>\n" +
                "    <市>HangZhou</市>\n" +
                "  </address>\n" +
                "</person>";
XStream xstream = new XStream(new DomDriver());
xstream.useAttributeFor(Address.class, "country");
xstream.processAnnotations(Person.class);
Person obj = (Person)xstream.fromXML(testXMl);
System.out.println(obj);
-----------------------------------------输出---------------------------------------------
[firstName = jack,lastName = Ma,address = [country = China,province = ZheJiang,city = HangZhou]
```
**别名配置的方式**
* 可以通过类注解实现@XStreamAlias,比如XStreamAlias("person");采用这种方式的时候，需要注意xStream实例化的时候，加上 xStream.processAnnotationsPerson.class); 通过注解方式的，一定要有这句话

* 可以通过配置Xstream设置实现；比如xStream.alias("person",Person.class);

**其他特性**
* 类成员别名，用xStream.aliasField(String alias, Class definedIn, String fieldName)。

* 将某一个类的属性，作为xml头信息的属性，而不是子节点，用xStream.useAttributeFor(Class definedIn, String fieldName)。

* 指定类成员属性别名，用 aliasAttribute(Class definedIn, String attributeName, String alias)，单独命名没有意义，还要通过useAttributeFor(Class definedIn, String fieldName) 应用到某个类上。如：将Person的firstName指定为XML属性并用别名表示。

* XStream默认当String类型的属性值为null时不封装到xml中。可以根据实际传xml情况，选择对象属性set空字符串还是null。
* 隐藏跟属性节点的时候，需要使用addImplicitCollection，比如：xStream.addImplicitCollection(Person.class,"lists");

# **How the Attack Works**
XStream实例化的类由它解析的XML元素的名称决定。
因为我们将XStream配置为知道Person类型，所以XStream在解析名为“Person”的XML元素时会实例化一个新的Person。
除了Person这样的用户定义类型之外，XStream还可以即时识别核心Java类型。例如，XStream可以从XML读取映射：
```java
String xml = "" 
    + "<map>" 
    + "  <element>" 
    + "    <string>foo</string>" 
    + "    <int>10</int>" 
    + "  </element>" 
    + "</map>";
XStream xStream = new XStream();
Map<String, Integer> map = (Map<String, Integer>) xStream.fromXML(xml);
```
XStream读取表示核心Java类型的XML的能力将有助于远程代码执行攻击的利用。

# **参考**
Xstream反序列化原理：
https://blog.csdn.net/weixin_39635657/article/details/111104938

XStream 组件高危漏洞分析与利用：
https://paper.seebug.org/1417/

Remote Code Execution with XStream：
https://www.baeldung.com/java-xstream-remote-code-execution

http://www.pwntester.com/blog/2013/12/23/rce-via-xstream-object-deserialization38/

远程代码执行漏洞复现：
https://www.jianshu.com/p/b600b6281aff

Xstream反序列化远程代码执行漏洞深入分析：
https://www.freebuf.com/articles/web/268553.html