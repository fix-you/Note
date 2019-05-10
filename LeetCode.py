# 322. 零钱兑换
"""
给定不同面额的硬币 coins 和一个总金额 amount。编写一个函数来计算可以凑成总金额所需的最少的硬币个数。
如果没有任何一种硬币组合能组成总金额，返回 -1。

示例 1:
输入: coins = [1, 2, 5], amount = 11
输出: 3
解释: 11 = 5 + 5 + 1

示例 2:
输入: coins = [2], amount = 3
输出: -1

考虑状态及转移方程
dp[i][j] 表示前 i 种面额的零钱表示总金额 j 的最少硬币个数
dp[-1][j] = ∞  dp[-1][0] = 0
dp[i][j] = min(dp[i][j], dp[i-1][j-coin_i*k] + k)
         = min(dp[i][j], dp[i][j-coin_i] + 1)

class Solution:
    def coinChange(self, coins, amount):
        dp = [amount + 1] * (amount + 5)
        dp[0] = 0
        for coin in coins:
            for i in range(amount + 1):
                if (i - coin >= 0):
                    dp[i] = min(dp[i], dp[i-coin] + 1)
        return -1 if dp[amount] >= amount + 1 else dp[amount]


test = Solution()

coins = [2147483647]
amount = 2
res = test.coinChange(coins, amount)
print(res)
"""



# 724. 寻找数组的中心索引
"""
def pivotIndex(nums):
    tmp, n, s = 0, len(nums), sum(nums)
    for i in range(n):
        if 2 * tmp  + nums[i] == s:
            return i
        tmp = tmp + nums[i]
    return -1

print(pivotIndex([1, 2, 3]))
"""



# 198. 打家劫舍
"""
dp[i] 表示抢到第 i 家为止最高金额
dp[0] 
dp[i] = max(dp[i-1], dp[i-2] + nums[i])



def rob(nums):
    n = len(nums)
    if n <= 2:
        return max(nums)
    dp = [0] * n
    dp[0] = nums[0]
    dp[1] = max(nums[0], nums[1])
    for i in range(2, n):
        dp[i] = max(dp[i - 1], dp[i - 2] + nums[i])
    return dp[n - 1]


# 真正起作用的只有三个变量
def rob_(nums):
    a, b = 0, 0
    for num in nums:
        # c = max(b, a + num) 中间值可以省掉
        a, b = b, max(b, a + num)
    return b


test1 = [1, 2, 3, 1]
test2 = [2, 7, 9, 3, 1]

print(rob_(test2))
"""



# 740. 删除与获得点数

"""
给定一个整数数组 nums ，你可以对它进行一些操作。
每次操作中，选择任意一个 nums[i] ，删除它并获得 nums[i] 的点数。同时，你必须删除每个等于 nums[i] - 1 和 nums[i] + 1 的元素。
开始你拥有 0 个点数。返回你能通过这些操作获得的最大点数。

示例 1:
输入: nums = [3, 4, 2]
输出: 6
解释: 
删除 4 来获得 4 个点数，因此 3 也被删除。
之后，删除 2 来获得 2 个点数。总共获得 6 个点数。

示例 2:
输入: nums = [2, 2, 3, 3, 3, 4]
输出: 9
解释: 
删除 3 来获得 3 个点数，接着要删除两个 2 和 4 。
之后，再次删除 3 获得 3 个点数，再次删除 3 获得 3 个点数。
总共获得 9 个点数。

注意:
nums的长度最大为20000。
每个整数nums[i]的大小都在[1, 10000]范围内。

分析：
翻译的过于死板，存在一点歧义，应该用和相连接，也就是左右相邻的都会被删掉。
这题与上面那个抢劫的类似，转换一下就能直接套用，题目说了一大圈，实际的含义就是不能拿相邻的。
输入: nums = [2, 2, 3, 3, 3, 4] => [0, 1*0, 2*2, 3*3, 4*1]

def rob(nums):
    a, b = 0, 0
    for num in nums:
        a, b = b, max(b, a + num)
    return b

def deleteAndEarn(nums):
    tmp = [0] * (len(nums) + 5)
    for num in nums:
        tmp[num] += num
    return rob(tmp)

print(deleteAndEarn([2, 2, 3, 3, 3, 4]))
"""



# 213. 打家劫舍 II
"""
与 1 的区别在于这里的房子是围起来的，形成圈，同样不能偷相邻的房子
"""



# 337. 打家劫舍 III
"""
在上次打劫完一条街道之后和一圈房屋后，小偷又发现了一个新的可行窃的地区。
这个地区只有一个入口，我们称之为“根”。 除了“根”之外，每栋房子有且只有一个“父“房子与之相连。
一番侦察之后，聪明的小偷意识到“这个地方的所有房屋的排列类似于一棵二叉树”。 
如果两个直接相连的房子在同一天晚上被打劫，房屋将自动报警。
"""



# 790. 多米诺和托米诺平铺




# 801. 使序列递增的最小交换次数



# 64. 最小路径和
"""
与爬楼梯类似

def minPathSum(grid):
    m , n = len(grid), len(grid[0])
    # dp = [[0] * m] * n 这种用法存的是引用，前面一改变，将全部变化
    dp = [[0 for i in range(m)] for j in range(n)]
    print(dp)
    for i in range(m):
        for j in range(n):
            if i == 0 and j == 0:
                dp[0][0] = grid[0][0]
            elif i == 0:  # 第 0 行只可能来自左边
                dp[i][j] = dp[i][j-1] + grid[i][j]
            elif j == 0:  # 第 0 列只可能来自上面
                dp[i][j] = dp[i-1][j] + grid[i][j]
            else:
                dp[i][j] = min(dp[i-1][j], dp[i][j-1]) + grid[i][j]
    print(dp)

# 可以直接复用 grid，减少空间复杂度
def minPathSum_(grid):
    m , n = len(grid), len(grid[0])
    for i in range(m):
        for j in range(n):
            if i == 0 and j == 0:
                continue
            elif i == 0:  # 第 0 行只可能来自左边
                grid[i][j] = grid[i][j-1] + grid[i][j]
            elif j == 0:  # 第 0 列只可能来自上面
                grid[i][j] = grid[i-1][j] + grid[i][j]
            else:
                grid[i][j] = min(grid[i-1][j], grid[i][j-1]) + grid[i][j]
    return grid[m-1][n-1]

test = [
  [1,3,1],
  [1,5,1],
  [4,2,1]
]

minPathSum(test)
minPathSum_(test)
"""



# 416. 分割等和子集
"""
只需要回答能不能分割，不用求具体的集合。
换句话来说，就是求出集合能表示多少种和，如果这个和恰好有 sum/2 即可，类似于之前求第n个丑数
dp[i][j] 为 1 表示前 i 个元素能表示出总和为 j
dp[-1][j] = False  dp[i][0] = False
dp[i][j] = dp[i-1][j-nums[i]] or dp[i][j]
return dp[n-1][sum/2]

但我们并不关心前多少个数，而且这有些重复的状态，可以直接降维

def canPartition(nums):
    s, n = sum(nums), len(nums)
    if  not nums or n == 0 or (s & 1) :
        return False
    dp = [False] * (s + 200)
    flag = s // 2
    dp[0] = True
    for num in nums:
        for j in range(s-1, -1, -1):  # 小技巧：倒序，否则会重复添加
            if dp[j]:
                dp[j + num] = True
        if dp[flag]:
            return True
    return False

print(canPartition([1, 2, 5]))

# 还可以用 dfs 做
"""



# 516. 最长回文子序列（有问题，过会再改
"""
求最长的回文子序列的长度，注意是序列，联想到最长递增子序列，这题只是把递增改为回文。
dp[i][j] 表示 [i, j] 最长的回文长度
dp[i][i] = 1
扩长有两个情况：
两旁的字母恰好相等
dp[i][j] = dp[i+1][j-1] + 2
不相等
dp[i][j] = max(dp[i-1][j], dp[i][j+1])
"""

def longestPalindromeSubseq(s):
    n = len(s)
    if not n: return 0
    dp = [[0] * (n + 3) for _ in range(n + 3)]
    dp[0][0] = 1
    for i in range(1, n):
        for j in range(i, n):
            if i == j:
                dp[i][i] = 1
                continue
            elif s[i - 1] == s[j]:
                dp[i][j] = dp[i - 1][j - 1] + 2
            else:
                dp[i][j] = max(dp[i - 1][j], dp[i][j + 1])
    return dp[0][n-1]

# print(longestPalindromeSubseq('abc'))



# 303. 区域和检索 - 数组不可变

"""
给定一个整数数组  nums，求出数组从索引 i 到 j  (i ≤ j) 范围内元素的总和，包含 i,  j 两点。
"""

class NumArray:
    def __init__(self, nums):
        pass
    def sumRange(self, i, j):
        pass



# 53. 最大子序和（应该是最大连续和）
"""
给定一个整数数组 nums ，找到一个具有最大和的连续子数组（子数组最少包含一个元素），返回其最大连续和。

dp[i][j] 表示 [i, j] 并且以 nums[j] 结尾的最大子序（以结尾作为连接，否则不好转移状态）
dp[i][i] = nums[i]
dp[i][j] = max(dp[i][j-1] + nums[j], nums[j])

由于是求的整个数组中的最大子序和，前面的 i 完全可以省略
=> dp[j] = max(dp[j-1] + nums[j], nums[j])

循环过程中真正需要的只有两个变量，可以再次降低空间复杂度
"""
def maxSubArray(nums):
    dp = [] * len(nums)
    for i in range(1, len(nums)):
        dp[i] = max(dp[i-1] + nums[i], nums[i])
    return max(dp)

# 实际上一个额外变量都不需要
def maxSubArray_(nums):
    for i in range(1, len(nums)):
        # nums[i] = max(nums[i-1] + nums[i], nums[i])
        # nums[i] += max(nums[i-1], 0)
        # 不用 max()，降低了一半的时间
        nums[i] += nums[i - 1] if nums[i - 1] > 0 else 0
    return max(nums)



# 121. 买卖股票的最佳时机

"""
给定一个数组，它的第 i 个元素是一支给定股票第 i 天的价格。
如果你最多只允许完成一笔交易（即买入和卖出一支股票），设计一个算法来计算你所能获取的最大利润。

1.尝试使用 dp 思想
dp[i] 表示在第 i 天卖出去的最大利润
dp[i] = 0
dp[i] = nums[i] - dp[i-1] - nums[i-1] （这有问题）
这种思路其实就是维护前 i-1 天的最低价，还没直接来的简单，弃之

2.get 到新点
price:[7, 1, 5, 3, 6, 4]
gain:   [-6, 4, -2, 3, -2]  # 每一天的收益，这正是我前面所想的，没表达出来
这里只需要求 gain 的最大连续和了
"""

def maxProfit(prices):
    if len(prices) <= 1: return 0  # 注意边界处理
    gain = [prices[i] - prices[i-1] for i in range(1, len(prices))]
    for i in range(1, len(gain)):
        gain[i] += gain[i-1] if gain[i-1] > 0 else 0
    return max(0, max(gain))  # 允许不交易，不会亏

# print(maxProfit([7, 6, 4, 3, 1]))



# 309. 最佳买卖股票时机含冷冻期
"""
给定一个整数数组，其中第 i 个元素代表了第 i 天的股票价格 。​
设计一个算法计算出最大利润。在满足以下约束条件下，你可以尽可能地完成更多的交易（多次买卖一支股票）:

你不能同时参与多笔交易（你必须在再次购买前出售掉之前的股票）。
卖出股票后，你无法在第二天买入股票 (即冷冻期为 1 天)。

示例:
输入: [1,2,3,0,2]
输出: 3 
解释: 对应的交易状态为: [买入, 卖出, 冷冻期, 买入, 卖出]
"""