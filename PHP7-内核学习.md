---
title: PHP7 内核学习
tags:
  - 笔记
abstract: PHP 进阶
top: 0
date: 2019-05-21 09:44:47
---

以下是学习 PHP 内核时所整理的笔记，感恩这些开源书籍。我以后写书也要开源 ：）

<http://www.php-internals.com/book/>

<https://www.kancloud.cn/nickbai/php7/363255>

<https://github.com/pangudashu/php7-internal>

## 源码目录结构

- 根目录: /

    这个目录包含的东西比较多，主要包含一些说明文件以及设计方案。 其实项目中的这些 README 文件是非常值得阅读的例如：

    - /README.PHP4-TO-PHP5-THIN-CHANGES 这个文件就详细列举了 PHP4 和 PHP5 的一些差异。
    - 还有有一个比较重要的文件 / CODING_STANDARDS，如果要想写 PHP 扩展的话，这个文件一定要阅读一下， 不管你个人的代码风格是什么样，怎么样使用缩进和花括号，既然来到了这样一个团体里就应该去适应这样的规范，这样在阅读代码或者别人阅读你的 代码是都会更轻松。

- **build** 这里主要放置一些和源码编译相关的一些文件，比如开始构建之前的 buildconf 脚本等文件，还有一些检查环境的脚本等。

- **ext** 官方扩展目录，包括了绝大多数 PHP 的函数的定义和实现，如 array 系列，pdo 系列，spl 系列等函数的实现，都在这个目录中。个人写的扩展在测试时也可以放到这个目录，方便测试和调试。

- **main** 这里存放的就是 PHP 最为核心的文件了，主要实现 PHP 的基本设施，这里和 Zend 引擎不一样，Zend 引擎主要实现语言最核心的语言运行环境。

- **Zend** Zend 引擎的实现目录，比如脚本的词法语法解析，opcode 的执行以及扩展机制的实现等等。

- **pear** “PHP 扩展与应用仓库”，包含 PEAR 的核心文件。

- **sapi** 包含了各种服务器抽象层的代码，例如 apache 的 mod_php，cgi，fastcgi 以及 fpm 等等接口。

- **TSRM** PHP 的线程安全是构建在 TSRM 库之上的，PHP 实现中常见的 * G 宏通常是对 TSRM 的封装，TSRM (Thread Safe Resource Manager) 线程安全资源管理器。

- **tests** PHP 的测试脚本集合，包含 PHP 各项功能的测试文件。

- **win32** 这个目录主要包括 Windows 平台相关的一些实现，比如 socket 的实现在 Windows 下和 * Nix 平台就不太一样，同时也包括了 Windows 下编译 PHP 相关的脚本。