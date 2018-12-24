# Python 笔记

functions decision control， 

loops and booleans，

simulation and design，

classes， 

data collection，

object-oriented design  algorithms

**单词**

+ mutable  易变的
+ invoke  v.  唤起，调用
+ shuffle  n. v.  搅乱，洗牌

list

+ list1 = [1, 3]
  list2 = list1
  list1[0] = 4

  list2 = [4, 3]  相当于引用？

+   def f(i, values = []):
  ​    values.append(i)
  ​    return values

  f(1)
  f(2)
  v = f(3)
  print(v)  

  **v = [1, 2, 3]**

+ random.shuffle(list1)  打乱顺序

+ list1 = [11, 2, 23] and list2 = [2, 11, 23], list1  !=  list2

+ insert(index, data)  index 从0开始

+ pop()  删除末尾元素 pop(index) 删除索引为 index 元素

+ remove() 删除指定元素

+ append() 在末尾追加元素

+ count() 输出元素出现次数

+ sort() 默认从小到大排序

+ reverse() 反转

+ extend() 在列表末尾一次性追加另一个序列中的多个值

+  If a key is not in the list, the binarySearch function returns **-(insertion point + 1)**

tuple

+ 一旦初始化就不能改变，string 也是？
+ 上面的初始化后不能改变也是有条件的， Python tuple is immutable if every element in the tuple is immutable. 比如 tuple 中有个 list，也是可以变得
+ 没有append，insert这些方法
+ 定义一个空元组()，
+ 定义一个元素的元组需要用(1,)，以此与单纯的小括号区分
+ The elements in a tuple or list are ordered!  =>  元素相对顺序确定，不是已排好序，能不能直接 [] 来访问

切片

+ [a:b]  => [a, b) 从 a 开始，不包括 b
+ a = 0 是可省略，b 为最后一个也可省略
+ 为负数时意味着倒数
+ [a:\b:c] c 为步长 ，L[::-1] 逆转
+ tuple也能切片，切出来仍然是一个tuple
+ L[1:-1]  =>  第一个到倒数第二个
+ L = (1,2)  => 2*L = (1, 2, 1, 2)

dict

+ {}  创建空 dict，{1,2} 是 set，d = {40:"john", 45:"peter"} 这样也是正确的
+ 直接 d['xxx'] ，如果 xxx 不存在就会报错：KeyError（事先 in 判断一下），此时可以用 get() ，不存在就会返回 none
+ 使用 pop() 删除 key，其对应的 value 也会被删掉
+ dict 无 delete 方法，可以 del d["john"]，不能 del d("john":40)
+ dict 之间无法进行 > 大小比较，但是可以判断是否相等

set

+ set() 创建空 set
+ list("abac")  =>  ['a', 'b', 'a', 'c']
+ tuple("abac")  =>  ('a', 'b', 'a', 'c')
+ set("abac")  =>  {'a', 'b', 'c'}  重复元素在set中自动被过滤
+ add() 添加元素，remove() 删除元素
+ 两个 set 进行 < , >比较，比的是 集合的包含关系
+ set 中的元素不能通过 [] 索引来获取
+ s1.issubset(s2)  =>  s1 是 s2 的子集
+ s1 ^ s2  =>  (s1-s2) | (s2-s1)
+ 2 * s1 是非法的
+ 不能 s1 + s2，取并集只能 | 

file IO

+ 如果文件不存在，`open()`函数就会抛出一个`IOError`的错误，并且给出错误码和详细的信息告诉你文件不存在
+ read(size)  每次读取size个字节内容，为写size则读取全部内容
+ readline() 每次读取一行内容，读取下一行
+ readlines() 一次读取所有内容并返回 list
+ os.path.exists('/etc/passwd') 判断是否存在
+ dialog