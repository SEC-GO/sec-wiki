---
title: Spring相关漏洞备忘
date: 2019-09-12 21:46:37
comments: true
toc: true
categories:
- Spring漏洞
tags:
- Spring漏洞

---

### 前言

Spring是一个开源框架，核心是控制反转（IoC）和面向切面（AOP）。简单来说，Spring是一个分层的JavaSE/EE full-stack(一站式) 轻量级开源框架。本文主要打算梳理一下和Spring相关的漏洞。

在介绍相关漏洞的时候，先要了解一下相关框架的基本特性功能用途。

## 一、Spring Boot相关漏洞

https://mp.weixin.qq.com/s/NnwtBW2uotCg_MWKJbpy5w

### 1. Spring cloud config server

Spring Cloud Config是Spirng Cloud下用于分布式配置管理的组件，分为Config-Server和Config-Client两个角色。 Config-Server负责集中存储/管理配置文件，Config-Client则可以从Config-Server提供的HTTP接口获取配置文件使用。

靶场环境：https://github.com/pe4ch/cve-hub/tree/master/cve-2019-3799

https://github.com/pe4ch/cve-hub/tree/master/cve-2019-3799

#### CVE-2019-3799
任意文件下载
Severity is high unless otherwise noted.
* Spring Cloud Config 2.1.0 to 2.1.1
* Spring Cloud Config 2.0.0 to 2.0.3
* Spring Cloud Config 1.4.0 to 1.4.5
* Older unsupported versions are also affected

https://xz.aliyun.com/t/4844

https://github.com/mpgn/CVE-2019-3799.git

#### CVE-2020-5405
Severity is high unless otherwise noted.
Older unsupported versions are also affected.
* Spring Cloud Config 2.2.0 to 2.2.1
* Spring Cloud Config 2.1.0 to 2.1.6

https://blog.riskivy.com/cve-2020-5405-spring-cloud-config-server-%E7%9B%AE%E5%BD%95%E7%A9%BF%E8%B6%8A/

http://www.lmxspace.com/2020/03/09/spring-cloud-config-server-%E8%B7%AF%E5%BE%84%E7%A9%BF%E8%B6%8A%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90%E3%80%90CVE-2020-5405%E3%80%91/

### 2. Spring boot actuator
https://xz.aliyun.com/t/4258

http://radiosong.cn/index.php/2019/04/03/1.html

靶场环境：https://github.com/veracode-research/actuator-testbed

https://www.veracode.com/blog/research/exploiting-spring-boot-actuators

https://lucifaer.com/2019/03/11/Attack%20Spring%20Boot%20Actuator%20via%20jolokia%20Part%201/

## 二、Spring messaging

#### CVE-2018-1270
影响版本
* Spring Framework 5.0 to 5.0.4.
* Spring Framework 4.3 to 4.3.14
* 已不支持的旧版本仍然受影响

修复版本
* 5.0.x 用户升级到5.0.5版本
* 4.3.x 用户升级到4.3.15版本

https://github.com/CaledoniaProject/CVE-2018-1270.git

#### CVE-2018-1275
由于可能官方版本发布流程或代码管理上所犯低级错误，导致4.3.14-4.3.15版本升级中该漏洞所涉及文件并未更新，所以CVE-2018-1270在4.3.14版本中并未修复，就有了最新的CVE-2018-1275漏洞，并在4.3.16版本中得到了修复。


## 三、Spring data

#### CVE-2017-8046
https://github.com/m3ssap0/SpringBreakVulnerableApp

#### CVE-2018-1273
https://github.com/knqyf263/CVE-2018-1273.git

https://github.com/jas502n/cve-2018-1273.git

#### CVE-2018-1259
https://paper.seebug.org/600/

## 四、Spring Web Flow
#### CVE-2017-4971
https://github.com/cved-sources/cve-2017-4971.git

## 五、Spring Security Oauth2
#### CVE-2016-4977
https://paper.seebug.org/70/
#### CVE-2018-1260
https://paper.seebug.org/597/
