# re之路

## 每天学点新东西

```
exeinfo 可以看到壳信息
upx -d  # 脱壳
```



## 汇编基础

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
# 寄存器
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


# 数据类型及声明
var db ?   ; 声明一个字节，未初始化
var db 64  ; 声明一个字节，初始值为 64
db 10	   ; 声明一个没有 label 的字节，值为 10
var dw ?   ; 2 字节
var dd 40  ; 4 字节
arr dd 1, 2, 3  ; 数组，初始值为 1, 2, 3
arr db 10 dup(?)  ; 10个元素的数组，未初始化
arr dd 100 dup(0) ; 100 个元素，初始化为 0
str db 'hello',0  ; 字符串，注意 0 结尾


# 寻址模式
mov eax, [ebx]  ; 将 ebx 值指示的内存地址中的 4 个字节传送到 eax 中
mov [var], ebx  ; 将 ebx 的内容传送到 var 值指示的内存地址中
movsx dest, src  ; 8 / 16 bits => 16 / 32 bits，扩展传送


# 常用指令
push src  ; 将 src 的数据存入栈中，不允许使用立即数寻址方式。
pushad  ;通用寄存器全入栈
pop dst  ; 用 dst 接收出栈数据，不能使用 cs 段寄存器
popad  ; 通用寄存器依次出栈

dumpregs  ; 显示所有寄存器信息
dumpmem  ; 显示所有内存信息


inc reg/mem  ; ++
dec reg/mem  ; --

xlat  ; 换码指令，默认 al 寄存器？

xchg reg, mem/reg  ; 交换两操作数内容
; 两操作数中必须有一个在寄存器中
; 操作数不能为段寄存器和立即数
; 源和目的操作数类型要一致

shl opr, cnt  ; 逻辑左移 cnt 位
shr opr, cnt
sal opr, cnt  ; 算术左移，同逻辑左移
sar opr, cnt
rol opr, cnt  ; 循环左移
ror opr, cnt

call writestring  ; 显示 edx 中的值
readstring buffer ; 输入字符串存到 buffer？

JE   ;等于则跳转
JNE  ;不等于则跳转

JZ   ;为 0 则跳转
JNZ  ;不为 0 则跳转

JS   ;为负则跳转
JNS  ;不为负则跳转

JC   ;进位则跳转
JNC  ;不进位则跳转

JO   ;溢出则跳转
JNO  ;不溢出则跳转

JA   ;无符号大于则跳转
JNA  ;无符号不大于则跳转
JAE  ;无符号大于等于则跳转
JNAE ;无符号不大于等于则跳转

JG   ;有符号大于则跳转
JNG  ;有符号不大于则跳转
JGE  ;有符号大于等于则跳转
JNGE ;有符号不大于等于则跳转

JB   ;无符号小于则跳转
JNB  ;无符号不小于则跳转
JBE  ;无符号小于等于则跳转
JNBE ;无符号不小于等于则跳转

JL   ;有符号小于则跳转
JNL  ;有符号不小于则跳转
JLE  ;有符号小于等于则跳转
JNLE ;有符号不小于等于则跳转

JP   ;奇偶位置位则跳转
JNP  ;奇偶位清除则跳转
JPE  ;奇偶位相等则跳转
JPO  ;奇偶位不等则跳转

; 输入输入函数
readint
; 返回值：cf = 0  => 输入存放在 eax 中，cf = 1  =>  输入无效

writeint
; 输出 eax 中的整数

; 类型 ptr 内存操作数或标号

cmp dword ptr [edx + 4*esi], 8  ; 强转后直接能比较

mov eax, 0
mov ecx, 3
lea edi, [esp + 4]
rep stosed  ; 重复？

; 函数写完了记得 ret
sub esp, 8
add esp 12  ; 注意回收栈中分配空间
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