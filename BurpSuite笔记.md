若 Burp 无法抓取 DVWA 等本地包，代理设置中删除 `不使用代理` ：<u>localhost,127.0.0.1</u> 即可

## 全局参数设置和使用

+ Project option

## 目录与文件扫描

## 暴力破解后台

## 暴力破解一句话木马

## 配合 sqlmap 实现被动式注入发现

## 突破文件上传

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


## 数据获取测试

