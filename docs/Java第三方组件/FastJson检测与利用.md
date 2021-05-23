# FastJson漏洞原理与检测、利用方式研究
# FastJson简介
FastJson 是阿⾥巴巴的开源 JSON 解析库，它可以解析 JSON 格式的字符串，⽀持将 Java Bean 序列
化为 JSON 字符串，也可以从JSON字符串反序列化到 Java Bean。
## FastJson序列化
```java
public class TestBean {
    public String publicField;
    private String privateField;
    private Flag flag;

    public TestBean(){
        System.out.println("TestBean constructor has called.");
        this.publicField = "publicField";
        this.privateField = "privateField";
        this.flag = new Flag();
    }

    public String getPublicField() {
        System.out.println("getPublicField has called.");
        return publicField;
    }

    public void setPublicField(String publicField) {
        System.out.println("setPublicField has called.");
        this.publicField = publicField;
    }

    public String getPrivateField() {
        System.out.println("getPrivateField has called.");
        return privateField;
    }

    public void setPrivateField(String privateField) {
        System.out.println("setPrivateField has called.");
        this.privateField = privateField;
    }

    public Flag getFlag() {
        System.out.println("getFlag has called.");
        return flag;
    }

    public void setFlag(Flag flag) {
        System.out.println("setFlag has called.");
        this.flag = flag;
    }
    @Override
    public String toString() {
        return "TestBean{" +
                "publicField='" + publicField + '\'' +
                ", privateField=" + privateField +
                ", flag=" + flag +
                '}';
    }
}

public class Flag {
    private String value;
    public Flag(){
        System.out.println("Flag constructor has called.");
        this.value = "flag{ctftest}";
    }
    public String getValue() {
        System.out.println("flag getValue has called.");
        return value;
    }
    public void setValue(String value) {
        System.out.println("flag setValue has called.");
        this.value = value;
    }
}
```
### **⾮⾃省调用toJSONString进行序列化**
```java
TestBean testBean = new TestBean();
String json1 = JSON.toJSONString(testBean);
System.out.println(json1);
```
```
// 输出：
TestBean constructor has called.
Flag constructor has called.
getFlag has called.
flag getValue has called.
getPrivateField has called.
getPublicField has called.
{"flag":{"value":"flag{ctftest}"},"privateField":"privateField","publicField":"publicField"}
```
构造⽅法并不是在序列化时触发的，⽽是在创建对象时触发的，除此之外，可以通过调试简单发现正常的Fastjson序列化会触发每⼀个属性的 get ⽅法。

### **⾃省调用toJSONString进行序列化**
```java
String json2 = JSON.toJSONString(testBean, SerializerFeature.WriteClassName);
System.out.println(json2);
```
```
// 输出：
getFlag has called.
flag getValue has called.
getPrivateField has called.
getPublicField has called.
{"@type":"com.dds.test.TestBean","flag":{"value":"flag{ctftest}"},"privateField":"privateField","publicField":"publicField"}
```
JSON 字符串中新增 @type 字段名，⽤来表明指定反序列化的⽬标对象类型为 TestBean。
## FastJson反序列化

# Fast源码分析

# FastJson历史漏洞

# 总结

https://zonghaishang.github.io/2018/09/30/Fastjson%E6%BA%90%E7%A0%81%E8%A7%A3%E6%9E%90-%E8%AF%8D%E6%B3%95%E5%92%8C%E8%AF%AD%E6%B3%95%E8%A7%A3%E6%9E%90-(%E4%B8%89)-%E9%92%88%E5%AF%B9%E5%AF%B9%E8%B1%A1%E5%AE%9E%E7%8E%B0%E8%A7%A3%E6%9E%90/

https://ananaskr.github.io/2020/05/20/fastjson-introduction/

https://paper.seebug.org/1192/

https://paper.seebug.org/994/

https://zonghaishang.gitbooks.io/fastjson-source-code-analysis/content/serializer/serializerWriter_part1.html