# re之路

## 每天学点新东西

```
windex 打开后发现为 upx 壳
upx -d  # 脱壳
```



## 汇编

程序模板

```assembly
TITLE Program Template  ; 标题可有可无

include irvine32.inc  ; 包含头文件

.data
; 数据区，声明全局变量
val1 dword 10000h
val2 dword 40000h
val3 dword 20000h
finalVal dword ?

.code
; 代码区
main PROC
	mov eax, val1		; start with 10000h
	add eax, val2		; add 40000h
	sub eax, val3		; subtract 20000h
	mov finalVal, eax	; store the result (30000h)
	call DumpRegs		; display the registers
	exit
main ENDP

funcName PROC

	ret
funcName ENDP

END main
```

入门

```assembly
; 寄存器
;    16 bits	8 bits	8 bits
eax     ax 		  ah 	  al 	; 累加器
ebx		bx		  bh	  bl	; 基址变址
ecx		cx		  ch	  cl	; 计数
edx 	dx		; 数据
esp 	sp		; 堆栈指针
ebp		bp		; 基址指针
edi		di		; 目的变址
esi		si		; 源变址
eip		ip		; 指令指针
eflags	flags 	; 标志


; 数据类型及声明
var db ?   ; 声明一个字节，未初始化
var db 64  ; 声明一个字节，初始值为 64
db 10	   ; 声明一个没有 label 的字节，值为 10
var dw ?   ; 双字节
var dd 40  ; 4 字节
arr dd 1, 2, 3  ; 数组，初始值为 1, 2, 3
arr db 10 dup(?)  ; 10个元素的数组，未初始化
arr dd 100 dup(0) ; 100 个元素，初始化为 0
str db 'hello',0  ; 字符串，注意 0 结尾


; 寻址模式
mov eax, [ebx]  ; 将 ebx 值指示的内存地址中的 4 个字节传送到 eax 中
mov [var], ebx  ; 将 ebx 的内容传送到 var 值指示的内存地址中


; 常用指令



; 输入输入函数
readint
; 返回值：cf = 0  => 输入存放在 eax 中，cf = 1  =>  输入无效

writeint
; 输出 eax 中的整数
```



## C语言

常用函数

```c
sprintf();
```





## 工具

pwndbg

pwntools

z3



**静态工具**

strings

file

binwalk

IDA