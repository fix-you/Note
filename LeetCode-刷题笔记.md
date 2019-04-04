## 前言

**要刷多少题？**

+ 每个类型 10 ~ 20 题（动态规划：多多益善）
+ 总共 200 ~ 300 题

**如何刷题？**

+ 同类型题目一起刷。e.g. 周一：树/链表，周二：搜索，周三：dp…
+ 第一遍：5分钟想不出来就看答案
+ 第二遍：尝试不看答案完整实现（一道题不要超过 60 分钟）
+ 第三遍：尝试快速实现，如果 15 ~ 20 分钟内实现不了就看答案

**看代码很重要！看代码很重要！看代码很重要！**

+ 看至少 3 ~ 5 种不同的实现，分析别人的代码，优缺点，为什么速度快/慢？
+ 学习新的语言 / 算法 / 数据结构 / API / 模板 / 最佳实践

**刷题过程中培养的能力**

+ 扩宽的思路，至少能看出该使用什么样的算法
+ 数据规模 –> 时间复杂度推算
+ 代码风格：
    + 一致性：命名 / 缩进 / 括号 / 换行
    + 有意义的变量名



算法是编程的灵魂，为了提高编程能力，从现在开始刷题。

唯有不断反思总结、勤学苦练，才能学有所成。

记住，你学的最痛苦的时候，就是你成长最快的时候。



## 模拟

## 数学

## 贪心

## 排序

## 二分查找

## 搜索

## 表/栈/队列

## 堆

##  $Treap$

## 几何

## 图论

## 分治

## 动态规划

### 背包问题



## 字符串

## 线段树

## 树状数组

## 倍增/$ST$表

## 数学

### 数论

### 博弈论




## 杂项

### 栈、队列、链表

+ 后缀表达式求值
>1.读入表达式一个字符
>2.若该字符为操作数，压入栈，转4
>3.若是运算符，从栈中弹出2个数，将运算结果再压入栈
>4.若表达式输入完毕，栈顶即表达式的结果，否则继续转




+ 循环数组实现队列

  这题很简单，循环数组实现一下。循环的处理要麻烦一点。直接定义一个变量记录队列中元素的个数，以此来判断空/满，这样的代码是最容易写的。另一个需要注意的地方就是start从0开始，end从-1开始。
```c++
class MyCircularQueue {
private:
    int* pp, size, start, end, len;
public:
    MyCircularQueue(int k) {
        pp = new int[k];  size = k;  start = 0;  end = -1;  len = 0;
    }

    bool enQueue(int value) {
        if(isFull())  return false;
        end++;  end %= size;  pp[end] = value;  len++;
        return true;
    }

    bool deQueue() {
        if(isEmpty()) return false;
        start++;  start %= size;  len--;
        return true;
    }
    
    int Front() {
        return isEmpty() ?  -1 : pp[start];
    }
    
    int Rear() {
        return isEmpty() ?  -1 : pp[end];
    }
    
    bool isEmpty() {
        return len == 0 ? true : false;
    }
    
    bool isFull() {
        return len == size ? true : false;
    }
};
```



+ 在栈的基本功能的基础上，再添加返回栈中最小元素的操作

  > 要求：1. pop、push、getMin 操作的时间复杂度都是 $O(1)$
  >          2.设计的栈类型可以使用现成的栈结构

  ```c++
  单独用一个栈来同步存储最小值
  class Stack{
  public:
  	stack<int> s;
  	stack<int> m;
  	
      int Pop(){
      	if(s.empty()) return -1;
      	s.pop();
      	m.pop();
      }
      
      void Push(int t){
      	s.push(t);
      	if(m.empty()) m.push(t);
      	else m.push(m.top() > t ? t : m.top());  // 始终保持栈顶最小
      }
      
      int getMin(){
      	return m.top();
      }
  };
  ```




+ 队列实现栈

  ```c++
  请一个help队列来支援
  class Stack{
  public:
  	queue<int> help;
  	queue<int> data;
  	
      void Push(int t){
      	data.push(t);
      }
  	
      int Top(){
      	if(date.empty()) return -1;
          while(data.size() != 1){
          	help.push(data.pop());
          }
          int res = data.pop();
          help.push(res);
          swap();
          return res;
      }
  	
      int Pop(){
      	if(date.empty()) return -1;
          while(data.size() > 1){
          	help.push(data.pop());
          }
          int res = data.pop();
          Swap();
          return res;
      }
      
      void Swap(){
      	queue<int> tmp = help;
      	help = data;
      	date = tmp;
      }
  };
  ```

+ 栈实现队列

  ```c++
  建两个栈。一个push栈，一个pop栈
  原则：push栈如果要往pop栈倒东西，一次要倒完
  	 pop栈不为空，一定不能倒
  ```




+ 猫狗队列

  给出宠物（Pet），猫（Cat）和狗（Dog）的类，实现一种猫狗队列，要求如下：

  ```c++
  class Pet{
  private:
      string type;
  public:
      Pet(string type){this.type = type;}
      string getPetType(){return this.type;}
  };
  
  class Dog: public Pet{
  public:
      Dog(){super("dog");}
  };
  
  class Cat: public Pet{
  public:
      Cat(){super("cat");}  // super？
  };
  ```
  - 用户可以调用add方法将cat类或者dog类的实例放入队列中
  - 用户可以调用pollAll方法将队列中所有的实例按照进队列的先后顺序依次弹出
  - 用户可以调用pollDog方法将队列中的dog类的实例按照进队列的先后顺序依次弹出
  - 用户可以调用pollCat方法将队列中的cat类的实例按照队列的先后顺序依次弹出
  - 用户可以调用isEmpty方法，检验队列中是否有dog类或cat类的实例
  - 用户可以调用isDogEmpty方法，检查队列中是否有dog类的实例
  - 用户可以调用isCatEmpty方法，检查队列中是否有cat类的实例



### 排序

+ 排序的稳定性：相同键的键值顺序在排序前后保持不变（即相同值的相对顺序不会被打乱）
+ 归并排序的额外空间复杂度可以变成 $O(1)$，但是非常难，详见 ~> <u>归并排序，内部缓存法</u>
+ 快速排序可做到稳定性，也很难，详见 ~> <u>01 stable sort</u> （01标准即元素间的性质差异，比如大小，奇偶）

#### 线性排序

+ 非基于比较的排序，与被排序的样本的实际数据状况很有关系，所以实际中并不经常使用
+ 时间复杂度$O(n)$ ，额外空间复杂度$O(n)$ 
+ 稳定的排序——一个萝卜一个坑



例，给定一个数组，求排序后相邻两数的最大差值。要求时间复杂度$O(n)$ ，且不能用非基于比较的排序

> 借用桶排序的思想，再来个鸽笼原理创造一个空桶
> 比如，n 个数放到 n+1 个桶里，其中min放到第一个桶，max放到最后一个桶
> 如此一来，最大差值就不可能来自同一个桶

```c++
int bucket(long num, long len, long Min, long Max){
    return (int)(num - Min) * len / (Max - Min);
}

int solve(vector<int>& nums){
    if(nums.size() == 0 || nums.size() == 1)  return 0;
    int len = nums.size();
    int Min = *max_element(nums.begin(), nums.end());
    int Max = *min_element(nums.begin(), nums.end());
    if(Min == Max)  return 0;
    bool fg[len+1] = {0};   // 记录桶是否为空
    int maxs[len+1] = {0};  // 每个桶的最大值
    int mins[len+1] = {0};  // 每个桶的最小值
    int bid = 0;
    for(int i = 0; i < len; i++){
        bid = bucket(nums[i], len, Min, Max);
        mins[bid] = fg[bid] ? min(mins[bid], nums[i]) : nums[i];
        maxs[bid] = fg[bid] ? max(maxs[bid], nums[i]) : nums[i];
        fg[bid] = true;
    }
    int res = 0, lastMax = maxs[0];
    for(int i = 1; i <= len; i++){
        if(fg[i]){
            res = max(res, mins[i] - lastMax);
            lastMax = maxs[i];
        }
    }
    return res;
}
```

### 桶排序

### 计数排序

### 基数排序

### 快排

```c++
int partion(int arr[], int l, int r) {
    int j = l;
    for(int i = l + 1; i <= r; i++) {
        if(arr[i] < arr[l]) {
            swap(arr[j+1], arr[i]);
            j++;
        }
    }
    swap(arr[l], arr[j]);
    return j;
}

void quicksort(int arr[], int l, int r) {
    if(l >= r) return;
    int p = partion(arr, l, r);
    quicksort(arr, l, p-1);
    quicksort(arr, p+1, r);
}
```

### 树

**定义：**

树：$n\ (n\ge0)$ 个结点构成的有限具有层次结构的集合。

当 $n=0$ 时，称为空树；

对于任一棵非空树 $(n>0)$，它具备以下性质：

+ 树中有一个称为“根$（root）$”的特殊结点，用 $r$ 表示；
+ 其余结点可分为 $m\ (m>0)$ 个互不相交的有限集 $T_1,T_2,...,T_m$，其中每个集合本身又是一棵树，称为原来树的”子树“$(SubTree)$

`注意点`：

+ 子树是不相交的；
+ 除了根节点，每个结点有且仅有一个父结点；
+ 一棵 N 个结点的树仅有 N-1 条边

**术语：**

+ 空树
+ 结点的度：结点的儿子结点个数
+ 树的度：树的所有结点中最大的度数
+ 结点的高度：在以 A 为根结点的子树中，从当前结点 A 到其各个叶结点的所有路径中最长路径的长度
+ 树的高度：根结点的高度
+ 结点的深度：从根结点到某个结点存在唯一的一条路径的长度
  + 根结点深度为 0 
  + 其余结点的深度为其父节点的深度加 1
+ 树的深度：树中所有结点中的最大层次是这棵树的深度
+ 叶结点（终端结点）：度为零的结点
+ 父结点：有子树的结点是其子树的根结点的父结点
+ 子结点：若 A 结点是 B 结点的父结点，则称 B 结点是 A 结点的子结点
+ 兄弟结点：具有同一父结点的各结点彼此是兄弟结点
+ 分枝结点（非终端结点）：度大于零的结点
+ 根结点：根节点有可能同时是叶节点
+ 内结点：非根结点的分枝结点
+ 路径和路径长度：
  + 从结点 $k_1$ 到 $k_j$ 的路径为一个结点序列 $k_1,k_2,...,k_j$，$k_i$ 是 $k_{i+1}$ 的父结点，其路径长度为 $j-1$。
  + 路径所包含边的个数为路径的长度
  + 任一结点到自身的路径长度为 $0$
+ 祖先结点：沿树根到某一结点路径上的所有结点都是这个结点的祖先结点 
+ 子孙结点：某一结点的子树中的所有结点是这个结点的子孙
+ 祖先和子孙，真祖先和真子孙
  + 自身是自身结点的祖先和子孙
  + 根结点没有真祖先，叶结点没有真子孙
  + 参考集合论中子集与真子集的概念理解
+ 结点的层次：规定根结点在 $1$ 层，其他任一结点的层数是其父结点的层数加 $1$
+ 子树：树中某一个结点以及其所有真子孙共同组成的一棵树
+ 有序树、无序树
+ 森林、有序森林：
  + $M\ (M\ge0)$ 棵互不相交的树的集合
  + 如果删除一棵树的树根结点，树根结点的所有子树构成一个森林

### 遍历

#### 含义：

`按照某种规则`对树中`所有结点`进行一次系统访问，即依次访问树中每个结点并且`仅访问一次`

#### 常见方式：

+ DFS——前序、中序、后序（对所在结点进行操作的顺序）
+ BFS

### 树的表示

> 要求：
>
> + 能够体现结点之间的父子关系/层次关系
> + 唯一性：可以唯一地表示一棵树
> + 完备性：可以表示任何一棵树

#### 父结点数组表示法

#### 儿子链表表示法

#### 左儿子右兄弟表示法

### 二叉树

任何一个结点均有左右次序之分

满二叉树：全部都满了

完全二叉树：只允许`最右下部分`有缺失，即如果按照满二叉树的方式编号的话，完全二叉树的编号跟满二叉树是一样的

二叉树的度不一定为2，可为0(没有结点)

#### 结构

```c++
struct node {
    int date;
    node* left;
    node* right;
}
```



#### 遍历

+ 递归


+ 非递归

### 堆

#### 建立

```c++
typedef struct HeapStruct *MaxHeap;
struct HeapStruct {
    int *data;
    int size;
    int capacity;
};

MaxHeap Create(int MaxSize) {
    MaxHeap H = new HeapStruct;
    H->data = new int[MaxSize + 1];
    H->size = 0;
    H->capacity = MaxSize;
    H->data[0] = MaxData;  // 哨兵
    return H;
}

void Insert(int x) {
    data[++k] = x;
    while(k > 1 && data[k/2] < data[k]) {
        swap(data[k/2], x);
        k /= 2;
    }
}
```

#### 删除

删掉顶端元素，数组最后一个元素挪上来，

顶端元素不断与两孩子中最大的那个进行交换，直到不能再交换。

```c++
void delete() {
    swap(data[k], data[1]);
    k--;
    while(2*k < size)
}
```

#### 堆排序

+ 建堆
+ pop出来

### 哈夫曼树

特点：

+ 没有度为1的结点
+ n 个叶子结点的哈夫曼树共有 2n - 1 个结点
+ 哈夫曼树的任意非叶结点的左右子树交换后仍是哈夫曼树

### 线索二叉树

### 平衡二叉树

### Hash

### 图

### 图的表示

### 图的遍历

### 最短路径

### 最小生成树

### 图匹配

### DAG

### 应用

+ 图的割点如何确定
+ 最短路径应用
+ 最小生成树应用
+ 拓扑排序应用
+ 抽象  =>  
+ 差分约束系统
+ 最长嵌套序列问题
+ 套汇问题
+ 路径判定问题
+ 路径计数问题
+ 过桥问题
+ 强连通图判定

### 错题

- 在一棵度为4的树T中，度2的结点数是为4，度3的结点数为2，度4的结点数为1.问该树的叶节点个数是多少？

  > 总的结点数 = 2\*4 + 3\*2 + 4*1 + 1
  >
  > 度不为1的结点数 = 4 + 2 + 1
  >
  > 叶结点数 = 总的 - 度不为1的

- 2-7 对于序列{ 49，38，65，97，76，13，27，50 }，按由小到大进行排序，下面哪一个是初始步长为4的希尔排序法第一趟的结果？

  > 第一趟：49与76；38与13；65与27；97与50 交换
  >
  > 答案：49,13,27,50,76,38,65,97

- 2-6 对一组包含10个元素的非递减有序序列，采用直接插入排序排成非递增序列，其可能的比较次数和移动次数分别是： 

  > 答案：45,44 **（暂时没搞懂）**

- 引入二叉线索树的目的：加快查找结点的前驱或后继的速度

- 堆排序不太清楚