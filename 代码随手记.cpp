# set的遍历
std::set<int>::iterator it = s.begin();
while(it!=s.end()) {
   cout<<*it++<<endl;//迭代器依次后移，直到末尾。
}

如果要查找一个元素用find函数，it = s.find(3);
这样it是指向3的那个元素的。可以通过rbegin，rend来逆向遍历
std::set<int>::reverse_iterator it = s.rbegin();
while(it!=s.rend()) {
	cout<<*it++<<endl;
}

if __name__=='__main__':
    n, m, k = [int(i) for i in input().split(' ')]
    st1 = set([int(i) for i in input().split(' ')])
    st2 = set([int(i) for i in input().split(' ')])
    st3 = set([int(i) for i in input().split(' ')])
    vst = [st1-st2, st2-st1,st1&st2, st1|st2]
    for i in range(len(vst)):
        st = set()
        j = 0
        while (1<<j) <= i:
            if i&(1<<j):
                st |= vst[1<<j]
            j += 1
        if st == st3:
            v = list(st3)
            v.sort()
            for i in v:
                print(str(i)+' ',end='')
            print('')
            exit()
    print('What a pity!')

unsigned int SDBMHash(char *str){
    unsigned int hash = 0;

    while (*str)    {
        // equivalent to: hash = 65599*hash + (*str++);
        hash = (*str++) + (hash << 6) + (hash << 16) - hash;
    }

    return (hash & 0x7FFFFFFF);
}

// RS Hash Function
unsigned int RSHash(char *str){
    unsigned int b = 378551;
    unsigned int a = 63689;
    unsigned int hash = 0;

    while (*str)    {
        hash = hash * a + (*str++);
        a *= b;
    }

    return (hash & 0x7FFFFFFF);
}

// JS Hash Function
unsigned int JSHash(char *str){
    unsigned int hash = 1315423911;

    while (*str)    {
        hash ^= ((hash << 5) + (*str++) + (hash >> 2));
    }

    return (hash & 0x7FFFFFFF);
}

// P. J. Weinberger Hash Function
unsigned int PJWHash(char *str){
    unsigned int BitsInUnignedInt = (unsigned int)(sizeof(unsigned int) * 8);
    unsigned int ThreeQuarters    = (unsigned int)((BitsInUnignedInt  * 3) / 4);
    unsigned int OneEighth        = (unsigned int)(BitsInUnignedInt / 8);
    unsigned int HighBits         = (unsigned int)(0xFFFFFFFF) << (BitsInUnignedInt - OneEighth);
    unsigned int hash             = 0;
    unsigned int test             = 0;

    while (*str)    {
        hash = (hash << OneEighth) + (*str++);
        if ((test = hash & HighBits) != 0)        {
            hash = ((hash ^ (test >> ThreeQuarters)) & (~HighBits));
        }
    }

    return (hash & 0x7FFFFFFF);
}

// ELF Hash Function
unsigned int ELFHash(char *str){
    unsigned int hash = 0;
    unsigned int x    = 0;

    while (*str)    {
        hash = (hash << 4) + (*str++);
        if ((x = hash & 0xF0000000L) != 0)        {
            hash ^= (x >> 24);
            hash &= ~x;
        }
    }

    return (hash & 0x7FFFFFFF);
}

// BKDR Hash Function
unsigned int BKDRHash(char *str){
    unsigned int seed = 131; // 31 131 1313 13131 131313 etc..
    unsigned int hash = 0;

    while (*str)    {
        hash = hash * seed + (*str++);
    }

    return (hash & 0x7FFFFFFF);
}

// DJB Hash Function
unsigned int DJBHash(char *str){
    unsigned int hash = 5381;

    while (*str)    {
        hash += (hash << 5) + (*str++);
    }

    return (hash & 0x7FFFFFFF);
}

// AP Hash Function
unsigned int APHash(char *str){
    unsigned int hash = 0;

    for (int i=0; *str; i++)    {
        if ((i & 1) == 0)
            hash ^= ((hash << 7) ^ (*str++) ^ (hash >> 3));
        else
            hash ^= (~((hash << 11) ^ (*str++) ^ (hash >> 5)));
    }

    return (hash & 0x7FFFFFFF);
}

#include<unordered_set>
unorderd_set基于哈希表
map实现的方式是红黑树。红黑树是一种近似于平衡的二叉查找树，里面的数据是有序的。查找的时间复杂度为O(logN)
unorderd_map用哈希表实现的，查找效率高，时间复杂度为O(1)，而额外的空间复杂度就高很多。
#include<unordered_map>
#还没弄懂？？？—— 就是遍历而已，基于容器的遍历
vector<int> nums;
vector<int> point(n+1, 0);
for(int i : nums)
	point[i] += i;

for(auto i : nums)
    i += 2;

// 编写一个程序判断给定的数是否为丑数（质因数只包含 2, 3, 5 的正整数）
bool isUgly(int num) {
	if(num == 0) return false;
	const vector<int> factors{2,3,5};
	for(const int factor : factors)
		while(num % factor == 0) num /= factor;
	
	return num == 1;
}

bool ok(int a, int b) {
      char buf[100];
      string s1, s2;
      sprintf(buf, "%d", a);
      s1 = string(buf);
      sprintf(buf, "%d", b);
      s2 = string(buf);
      rep(i, 0, sz(s1)) {
          if(s2.find(s1.substr(i, 1)) != string::npos)  return true;
          // npos is a static member constant value with the greatest possible 
		  // value for an element of type size_t.
          // As a return value, it is usually used to indicate no matches.
      }
      return false;
  }

#DFS棋盘问题		// 自带回溯
char G[10][10];
bool fg[10] = {0};  // 走过为真
int ans = 0, n, k;

void dfs(int cur, int x) {  // cur为已摆的棋子数， x 为行数
    if(cur == k) {
        ans++;
        return;
    }
    rep(i, x, n)
        rep(j, 0, n)
            if(G[i][j] == '#' && !fg[j]) {
                fg[j] = true;
                dfs(cur+1, i+1);  // 下一行继续摆下一个棋子
                fg[j] = false;
            }
}

int main() {
    while(sf("%d%d", &n, &k) == 2 && n != -1 && k != -1) {
        rep(i,0,n) sf("%s",G[i]);
        dfs(0, 0);  // 第一行开始摆
        pf("%d\n", ans); ans = 0;
    }
    return 0;
}

#DFS 联通块
char pic[maxn][maxn];
int m, n, idx[maxn][maxn];

void dfs(int r, int c, int id) {
  if(r < 0 || r >= m || c < 0 || c >= n) return;
  if(idx[r][c] > 0 || pic[r][c] != '@') return;
  idx[r][c] = id;
  for(int dr = -1; dr <= 1; dr++)				// 遍历r, c附近的八块
    for(int dc = -1; dc <= 1; dc++)				
      if(dr != 0 || dc != 0) dfs(r+dr, c+dc, id);
}

int main() {
  while(scanf("%d%d", &m, &n) == 2 && m && n) {
    for(int i = 0; i < m; i++) scanf("%s", pic[i]);
    memset(idx, 0, sizeof(idx));
    int cnt = 0;
    for(int i = 0; i < m; i++)
      for(int j = 0; j < n; j++)
        if(idx[i][j] == 0 && pic[i][j] == '@') dfs(i, j, ++cnt);
    printf("%d\n", cnt);
  }
  return 0;
}  
  
  
#bfs maze
char mm[N][N];
int fg[N][N] = {0}; // 记录有无走过
int n, m, x, y;  // n 行 m 列
vector<pair<int, int> > path;

bool bfs(int i, int j){ // i, j为起始位置
    queue<pair<int, int> > qq;
    qq.push(make_pair(i, j));
    while(!qq.empty()){
        int inext[] = {0, 0, -1, 1};
        int jnext[] = {-1, 1, 0, 0};
        int icur, jcur;
        for(int k=0; k<4; k++){  // 上下左右各来一次
            icur = qq.front().first + inext[k];
            jcur = qq.front().second + jnext[k];
            if(icur < 0 || icur >= n || jcur < 0 || jcur >= m || (icur == x && jcur == y)) continue;
            if(mm[icur][jcur] != '#' && !fg[icur][jcur]){
                qq.push(make_pair(icur, jcur));  // 可以到达则放入队列中
                fg[icur][jcur] = fg[qq.front().first][qq.front().second] + 1;
                // 能到达的话，步数为原基础上加1
            }
            if(mm[icur][jcur] == 'E'){
                cout<<fg[icur][jcur]<<endl;
                return true;
            }
        }
        qq.pop();  // 走了之后出队
    }
    return false;
}

int main(){
    cin.tie(0);ios::sync_with_stdio(false);
    cin>>n>>m;
    for(int i=0; i < n; i++){
        for(int j=0; j < m; j++){
            cin>>mm[i][j];
            if(mm[i][j] == 'S') x = i, y = j;  // 存储开始位置
        }
    }
    if(!bfs(x, y)) puts("-1");
    return 0;
}

//{{{ #include
#include <algorithm>
#include <iostream>
#include <cstring>
#include <vector>
#include <cstdio>
#include <string>
#include <cmath>
#include <queue>
#include <set>
#include <map>
#include <complex>
//#include <bits/stdc++.h>
//}}}
using namespace std;

typedef long long ll;
typedef long double ld;
typedef double db;
typedef pair<int,int> pii;
typedef vector<int> vi;

#define mp make_pair
#define fi first
#define se second
#define sf scanf
#define pf printf
#define pn printf("\n")
#define ls l,mid,rt<<1
#define rs mid+1,r,rt<<1|1
#define pb push_back
#define all(x) (x).begin(),(x).end()
#define de(x) cout << #x << "=" << x << endl
#define dd(x) cout<< #x<<" = "<<x<<" "
#define rep(i,a,b) for(int i=a;i<(b);++i)
#define per(i,a,n) for (int i=n-1;i>=a;i--)
#define mem(a,b) memset(a,b,sizeof(a))
#define sz(x) (int)(x).size()

const int INF=0x3f3f3f3f;
const double eps=1e-8;
const double PI=acos(-1.0);
const int N = 101010;

int sgn(double x){if(fabs(x)<eps)return 0;if(x<0)return -1;else return 1;}
ll gcd(ll a,ll b){return b==0?a:gcd(b,a%b);}

// fast-pow
int Pow(ll x,ll t,int p) {ll r=1;for(;t;t>>=1,x=x*x%p)if(t&1)r=r*x%p;return r;}

// add-mod
const int MOD = 1e9 + 7;
void pp(int &x,int d) {if((x+=d)>=MOD) x-=MOD;}
// minus-mod -> pp(a , P - x);
// multiply-mod
int mul(int a,int b){ return ll(a)*b%MOD;}
// inversion
int inverse(int x,int p) {return Pow(x,p-2,p);} // p should be prime

// tree-dp
vi g[N];
int sz[N];
void dfs(int c,int par){
  sz[c] = 1;
  for(auto t : g[c]) if(t != par){ // c++11
    dfs(t , c);
    sz[c] += sz[t];
  }
}

// dsu
int fa[N];
int F(int x){ return fa[x] == x ? x : fa[x] = F(fa[x]);}
void M(int x,int y){ fa[F(x)] = F(y);}

int main(){
  // swap
  int u = 0, v = 1;
  std::swap(u , v); // swap
  set<int> A , B;
  std::swap(A , B); // O(1)

  // minimal & maximal
  int a[20] , n = 20;
  rep(i,0,n) a[i] = i;
  cout << *std::max_element(a , a + n) << endl;// [a , a+n)
  cout << *std::min_element(a , a + n) << endl;

  // discretization
  vi V;// about 10 int
  sort(all(V));V.erase(unique(all(V)),V.end());
#define rk(x) upper_bound(all(V) , x) - V.begin()

  // deal with same value
  for(int i=0,j=0;i<sz(V);i=j) {
    for(j=i;j<sz(V)&&V[j]==V[i];++j);
    // Cal(i , j) //[i , j)
  }

  // multiple-loops
  int g[10][10] , m = 10;
  rep(i,0,m) rep(j,0,m) scanf("%d",&g[i][j]);

  // __builtin_popcount()
  int cnt1[1<<6];
  rep(i,1,1<<6) cnt1[i] = cnt1[i >> 1] + (i & 1);

  // sort
  int cnt[20];
  sort(all(V),[&](int a,int b){return cnt[a]<cnt[b];}); // c++11 
  vector<vi> Vv;
  sort(all(Vv));

  // sort with id
  vector<pii> p;
  rep(i,0,20) p.pb(mp(rand(),i));
  sort(all(p));

  // deal with subsets
  rep(mask,0,1<<10)
    for(int j=mask;j;j=(j-1)&mask)
      ;// Cal

  // high-dimensional prefix-sum
  int f[1<<10];
  rep(i,0,10) rep(j,0,1<<10) if(j>>i&1) pp(f[j],f[j^(1<<i)]);

  // permutation
  rep(i,0,7) a[i] = i;
  do{
    // Cal;
  }while(next_permutation(a , a + 7));

  // fill function
  std::fill(a , a + 20 , 0);// fill any number

  // reference
  int &r = f[10];
  rep(i,0,10) r += i;

  // ternary operator
  int C[10][10] = {{1}};
  rep(i,1,10) rep(j,0,i+1) C[i][j] = j ? (C[i-1][j-1] + C[i-1][j]) : 1;

  return 0;
}


#二分递归求和
sum(int a[],int lo,int hi) {
	if(lo==hi) return a[lo];
	int mi = (lo + hi)>>1;
	return sum(a,lo,mi) + sum(a,mi+1,hi);
}

#RMQ问题
void ST(int n) {//打表
    for (int i = 0; i < n; i++)//dp[i][j] ==> 从i开始,长度为2^j元素中的最值
        dp[i][0] = A[i];//A[i]为待查询的序列
    for (int j = 1; (1<<j) <= n; j++) 
        for (int i = 0; i+(1<<j)-1 < n; i++) // 1<<(j-1) 等价于 2^(j-1)
            dp[i][j] = max(dp[i][j-1], dp[i+(1<<(j-1))][j-1]);
}

int RMQ(int l, int r) {//查询
    int k = 0;
    while ((1<<(k+1)) <= r-l+1) k++;
    return max(dp[l][k], dp[r-(1<<k)+1][k]);
}

#杂项
字符串常用函数
	反转 string s(str1.rbegin(),str1.rend());
unsigned long long ---> %I64u
牛逼的全排列函数  // next_permutation()
关闭同步流  // ios::sync_with_stdio(false);cin.tie(0);


//{{{ #include
#include <algorithm>
#include <iostream>
#include <cstring>
#include <vector>
#include <cstdio>
#include <string>
#include <cmath>
#include <queue>
#include <set>
#include <map>
#include <complex>
//#include <bits/stdc++.h>
//}}}
using namespace std;

typedef long long ll;
typedef long double ld;
typedef double db;
typedef pair<int,int> pii;
typedef vector<int> vi;

#define mp make_pair
#define fi first
#define se second
#define sf scanf
#define pf printf
#define pn printf("\n")
#define ls l,mid,rt<<1
#define rs mid+1,r,rt<<1|1
#define pb push_back
#define all(x) (x).begin(),(x).end()
#define de(x) cout << #x << "=" << x << endl
#define dd(x) cout<< #x<<" = "<<x<<" "
#define rep(i,a,b) for(int i=a;i<(b);++i)
#define per(i,a,n) for (int i=n-1;i>=a;i--)
#define mem(a,b) memset(a,b,sizeof(a))
#define sz(x) (int)(x).size()

const int INF=0x3f3f3f3f;
const double eps=1e-8;
const double PI=acos(-1.0);
const int N = 101010;

int sgn(double x){if(fabs(x)<eps)return 0;if(x<0)return -1;else return 1;}
ll gcd(ll a,ll b){return b==0?a:gcd(b,a%b);}

// fast-pow
int Pow(ll x,ll t,int p) {ll r=1;for(;t;t>>=1,x=x*x%p)if(t&1)r=r*x%p;return r;}

// add-mod
const int MOD = 1e9 + 7;
void pp(int &x,int d) {if((x+=d)>=MOD) x-=MOD;}
// minus-mod -> pp(a , P - x);

// multiply-mod
int mul(int a,int b){ return ll(a)*b%MOD;}

// inversion
int inverse(int x,int p) {return Pow(x,p-2,p);} // p should be prime

// tree-dp
vi g[N];
int sz[N];
void dfs(int c,int par){
  sz[c] = 1;
  for(auto t : g[c]) if(t != par){ // c++11
    dfs(t , c);
    sz[c] += sz[t];
  }
}

// dsu
int fa[N];
int F(int x){ return fa[x] == x ? x : fa[x] = F(fa[x]);}
void M(int x,int y){ fa[F(x)] = F(y);}

int main(){
  // swap
  int u = 0, v = 1;
  std::swap(u , v); // swap
  set<int> A , B;
  std::swap(A , B); // O(1)

  // minimal & maximal
  int a[20] , n = 20;
  rep(i,0,n) a[i] = i;
  cout << *std::max_element(a , a + n) << endl;// [a , a+n)
  cout << *std::min_element(a , a + n) << endl;

  // discretization
  vi V;// about 10 int
  sort(all(V));V.erase(unique(all(V)),V.end());
#define rk(x) upper_bound(all(V) , x) - V.begin()

  // deal with same value
  for(int i=0,j=0;i<sz(V);i=j) {
    for(j=i;j<sz(V)&&V[j]==V[i];++j);
    // Cal(i , j) //[i , j)
  }

  // multiple-loops
  int g[10][10] , m = 10;
  rep(i,0,m) rep(j,0,m) scanf("%d",&g[i][j]);

  // __builtin_popcount()
  int cnt1[1<<6];
  rep(i,1,1<<6) cnt1[i] = cnt1[i >> 1] + (i & 1);

  // sort
  int cnt[20];
  sort(all(V),[&](int a,int b){return cnt[a]<cnt[b];}); // c++11 
  vector<vi> Vv;
  sort(all(Vv));

  // sort with id
  vector<pii> p;
  rep(i,0,20) p.pb(mp(rand(),i));
  sort(all(p));

  // deal with subsets
  rep(mask,0,1<<10)
    for(int j=mask;j;j=(j-1)&mask)
      ;// Cal

  // high-dimensional prefix-sum
  int f[1<<10];
  rep(i,0,10) rep(j,0,1<<10) if(j>>i&1) pp(f[j],f[j^(1<<i)]);

  // permutation
  rep(i,0,7) a[i] = i;
  do{
    // Cal;
  }while(next_permutation(a , a + 7));

  // fill function
  std::fill(a , a + 20 , 0);// fill any number

  // reference
  int &r=f[10];
  rep(i,0,10) r+=i;

  // ternary operator
  int C[10][10] = {{1}};
  rep(i,1,10) rep(j,0,i+1) C[i][j] = j ? (C[i-1][j-1] + C[i-1][j]) : 1;

  return 0;
}


经典
1.1埃拉托斯特尼筛法

int prime[maxn];  
bool is_prime[maxn];

int sieve(int n){
    int p = 0;
    rep(i,0,n+1)
        is_prime[i] = true;
    is_prime[0] = is_prime[1] = false;
    rep(i,2,n+1){   //  注意数组大小是n
        if(is_prime[i]){
            prime[p++] = i;
            for(int j = i + i; j <= n; j += i)  //  轻剪枝，j必定是i的倍数
                is_prime[j] = false;
        }
    }
    return p;   //  返回素数个数
}

1.2素因子分解

void solve(int n)
{
	int sol[100],j=0,temp = n;
	while(n%2==0) {
		sol[j++] = 2;
		n /= 2;
	}
	for(int i=3;i<=sqrt(n);i+=2)
		while(n%i==0) {
			sol[j++] = i;
			n /= i;
		}
	if(n>1)
		sol[j++] = n;//存最后一位
	cout<<temp<<'='<<sol[0];
	for(int i=1;i<j;i++)
		cout<<'*'<<sol[i];
}

2.1快速幂

typedef long long ll;
ll pw(ll a,ll b){
    ll ans = 1;
    while(b){
        if(b&1)//一个数 & 1 的结果就是取二进制的最末位,x&1==0为偶，x&1==1为奇
            ans = ans*a;
        a *= a;
        b >>= 1;//>>为二进制去掉最后一位
    }
    return ans;
}

ll mod(ll a,ll b,ll c) {
	ll ans = 1;
	while(b) {
		if(b&1)
			ans = (ans*a)%c;
		a = (a*a)%c;
		b >>= 1;
	}
	return ans;
}

2.2快速乘

ll Mul(ll a,ll b,ll mod)
{
    ll res = 0;
    while(b>0){
        if(b&1) res=(res+a)%mod;        
        a = (a+a)%mod;
		b >>= 1;
    }
    return res;
}
//快速乘中的%用加法更快
ll mul(ll a, ll b, ll c) {
    ll res=0;
    while (b) {
        if(b & 1) {
            res += a;
            if (res >= c) res -= c;
        }
        a <<= 1;
        if(a >= c) a -= c;
        b >>= 1;
    }
    return res;
}

2.3矩阵快速幂//处理(高阶)递推式
const int N=10;
int tmp[N][N];
void multi(int a[][N],int b[][N],int n) {
    memset(tmp,0,sizeof tmp);
    for(int i=0;i<n;i++)
        for(int j=0;j<n;j++)
			for(int k=0;k<n;k++)
				tmp[i][j]+=a[i][k]*b[k][j];
    for(int i=0;i<n;i++)
        for(int j=0;j<n;j++)
			a[i][j]=tmp[i][j];
}
int res[N][N];
void Pow(int a[][N],int n){
    memset(res,0,sizeof res);//n是幂，N是矩阵大小
    for(int i=0;i<N;i++) res[i][i]=1;
    while(n)
    {
        if(n&1)
            multi(res,a,N);//res=res*a;复制直接在multi里面实现了；
        multi(a,a,N);//a=a*a
        n>>=1;
    }
}

2.4Euler函数

ll euler(ll n){
    ll m=floor(sqrt(n+0.5)),ans=n;
    for(ll i=2;i<=m;i++){
        if(n%i==0){
            ans=ans/i*(i-1);
            while(n%i==0)
                n/=i;
        }
    }
    if(n>1)
        ans=ans/n*(n-1);
    return ans;
}

int euler_phi(int n) {
	int m = (int)sqrt(n + 0.5);
	int ans = n;
	rep(i,2,m+1)
		if(n%i==0) {
			ans = ans / i * (i-1);
			while(n%i==0) n /= i;
		}
	if(n>1) ans = ans / n *(n-1);
}

//nlog(log(n))
void phi_table(int n,int* phi) {
	rep(i,2,n+1) phi[i] = 0;
	phi[1] = 1;
	rep(i,2,n+1) 
		if(![phi[i])
			for(int j=i;j<=n;j+=i) {
				if(!phi[j]) phi[j] = j;
				phi[j] = phi[j] / i * (i-1);
			}
}

3.大数模拟

大数加法

string add1(string s1, string s2){
    if (s1 == "" && s2 == "")   return "0";
    if (s1 == "")   return s2;
    if (s2 == "")   return s1;
    string maxx = s1, minn = s2;
    if (s1.length() < s2.length()){
        maxx = s2;
        minn = s1;
    }
    int a = maxx.length() - 1, b = minn.length() - 1;
    for (int i = b; i >= 0; --i){
        maxx[a--] += minn[i] - '0'; //  a一直在减 ， 额外还要减个'0'
    }
    for (int i = maxx.length()-1; i > 0;--i){
        if (maxx[i] > '9'){
            maxx[i] -= 10;//注意这个是减10
            maxx[i - 1]++;
        }
    }
    if (maxx[0] > '9'){
        maxx[0] -= 10;
        maxx = '1' + maxx;
    }
    return maxx;
}

大数阶乘

#include <iostream>
#include <cstdio>

using namespace std;

typedef long long ll;

const int maxn = 100010;

int num[maxn], len;

/*
    在mult函数中，形参部分：len每次调用函数都会发生改变，n表示每次要乘以的数，最终返回的是结果的长度
    tip: 阶乘都是先求之前的(n-1)!来求n!
    初始化Init函数很重要，不要落下
*/

void Init() {
    len = 1;
    num[0] = 1;
}

int mult(int num[], int len, int n) {
    ll tmp = 0;
    for(ll i = 0; i < len; ++i) {
         tmp = tmp + num[i] * n;    //从最低位开始，等号左边的tmp表示当前位，右边的tmp表示进位（之前进的位）
         num[i] = tmp % 10; //  保存在对应的数组位置，即去掉进位后的一位数
         tmp = tmp / 10;    //  取整用于再次循环,与n和下一个位置的乘积相加
    }
    while(tmp) {    //  之后的进位处理
         num[len++] = tmp % 10;
         tmp = tmp / 10;
    }
    return len;
}

int main() {
    Init();
    int n;
    n = 1977; // 求的阶乘数
    for(int i = 2; i <= n; ++i) {
        len = mult(num, len, i);
    }
    for(int i = len - 1; i >= 0; --i)
        printf("%d",num[i]);    //  从最高位依次输出,数据比较多采用printf输出
    printf("\n");
    return 0;
}

4.GCD
int gcd(int a, int b) {
    return b==0 ? a : gcd(b,a%b);
}

5.LCM
//利用gcd即可，最大公约数 = a*b/gcd(a,b);

6.全排列 //next_permutation()

void Pern(int list[], int k, int n) {   //k表示前k个数不动仅移动后面n-k位数
    if (k == n - 1) {
        rep(i,0,n) {
            printf("%d", list[i]);
        }
        printf("\n");
    }
	else {
        rep(i,k,n) {   				//输出的是满足移动条件所有全排列
            swap(list[k], list[i]);
            Pern(list, k + 1, n);
            swap(list[k], list[i]);
        }
    }
}

7.二分查找

int binary_search(int* arr,int target) {
	//在arr[l,r]之中查找target
	int l = 0,r = n - 1;	
	while(l<=r) {
		int mid = l + (r - l)/2;//防止r+l太大溢出而采用减法
		if(arr[mid] == target)
			return mid;
		if(target < arr[mid])
			r = mid - 1;
		else
			l = mid + 1;
	}
	return -1;
} 

数据结构
并查集
8.并查集

int pa[n];						// 储存根节点

void makeSet(){
    for(int i = 0; i < n; i++)
        pa[i] = i;
}

int findRoot(int x){
    return pa[x] != x ? pa[x] = findRoot(pa[x]) : x; 
}

void Union(int x, int y){
    int a = findRoot(x);
    int b = findRoot(y);
    pa[a] = b;
}

图论
最小生成树


9.Kruskal//适用于 稀疏图 求最小生成树
/*
    第一步：点、边、加入vector，把所有边按从小到大排序
    第二步：并查集部分 + 下面的code
*/

void Kruskal() {    
    int ans = 0;    
    for (int i = 0; i<len; i++) {    
        if (Find(edge[i].a) != Find(edge[i].b)) {    
            Union(edge[i].a, edge[i].b);    
            ans += edge[i].len;    
        }    
    }    
}    

10.Prim
/*
    |适用于 稠密图 求最小生成树|
    |堆优化版，时间复杂度：O(elgn)|
*/

struct node {  
    int v, len;  
    node(int v = 0, int len = 0) :v(v), len(len) {}  
    bool operator < (const node &a)const {  // 加入队列的元素自动按距离从小到大排序  
        return len> a.len;  
    }  
};

vector<node> G[maxn];
int vis[maxn];
int dis[maxn];

void init() {  
    for (int i = 0; i<maxn; i++) {  
        G[i].clear();  
        dis[i] = INF;  
        vis[i] = false;  
    }  
}  
int Prim(int s) {  
    priority_queue<node> Q; // 定义优先队列  
    int ans = 0;  
    Q.push(node(s,0));  // 起点加入队列  
    while (!Q.empty()) {   
        node now = Q.top(); Q.pop();  // 取出距离最小的点  
        int v = now.v;  
        if (vis[v]) continue;  // 同一个节点，可能会推入2次或2次以上队列，这样第一个被标记后，剩下的需要直接跳过。  
        vis[v] = true;  // 标记一下  
        ans += now.len;  
        for (int i = 0; i<G[v].size(); i++) {  // 开始更新  
            int v2 = G[v][i].v;  
            int len = G[v][i].len;  
            if (!vis[v2] && dis[v2] > len) {   
                dis[v2] = len;  
                Q.push(node(v2, dis[v2]));  // 更新的点加入队列并排序  
            }  
        }  
    }  
    return ans; 
}  


Bellman-Ford
单源最短路

11.Dijkstra

/*
    |适用于边权为正的有向图或者无向图|
    |求从单个源点出发，到所有节点的最短路|
    |优化版：时间复杂度 O(elbn)|
*/

struct node {  
    int v, len;  
    node(int v = 0, int len = 0) :v(v), len(len) {}  
    bool operator < (const node &a)const {  //  距离从小到大排序  
        return len > a.len;  
    }  
};  

vector<node>G[maxn];  
bool vis[maxn];  
int dis[maxn];

void init() {  
    for (int i = 0; i<maxn; i++) {  
        G[i].clear();  
        vis[i] = false;  
        dis[i] = INF;  
    }  
}  
int dijkstra(int s, int e) {  
    priority_queue<node>Q;  
    Q.push(node(s, 0)); //  加入队列并排序  
    dis[s] = 0;  
    while (!Q.empty()) {  
        node now = Q.top();     //  取出当前最小的  
        Q.pop();  
        int v = now.v;  
        if (vis[v]) continue;   //  如果标记过了, 直接continue  
        vis[v] = true;  
        for (int i = 0; i<G[v].size(); i++) {   //  更新  
            int v2 = G[v][i].v;  
            int len = G[v][i].len;  
            if (!vis[v2] && dis[v2] > dis[v] + len) {  
                dis[v2] = dis[v] + len;  
                Q.push(node(v2, dis[v2]));  
            }  
        }  
    }  
    return dis[e];  
}  

12.最短路径快速算法（Shortest Path Faster Algorithm）

/*
    |队列优化|
    |可处理负环|
*/

vector<node> G[maxn];
bool inqueue[maxn];
int dist[maxn];

void Init() {  
    for(int i = 0 ; i < maxn ; ++i) {  
        G[i].clear();  
        dist[i] = INF;  
    }  
}  

int SPFA(int s,int e) {  
    int v1,v2,weight;  
    queue<int> Q;  
    memset(inqueue,false,sizeof(inqueue)); // 标记是否在队列中  
    memset(cnt,0,sizeof(cnt)); // 加入队列的次数  
    dist[s] = 0;  
    Q.push(s); // 起点加入队列  
    inqueue[s] = true; // 标记  
    while(!Q.empty()) {  
        v1 = Q.front();  
        Q.pop();  
        inqueue[v1] = false; // 取消标记  
        for(int i = 0 ; i < G[v1].size() ; ++i) { // 搜索v1的链表  
            v2 = G[v1][i].vex;  
            weight = G[v1][i].weight;  
            if(dist[v2] > dist[v1] + weight) { // 松弛操作  
                dist[v2] = dist[v1] + weight;  
                if(inqueue[v2] == false) {  // 再次加入队列  
                    inqueue[v2] = true;  
                    //cnt[v2]++;  // 判负环  
                    //if(cnt[v2] > n) return -1;  
                    Q.push(v2);  
                }
            } 
        }  
    }  
    return dist[e];  
}

/*
    不断的将s的邻接点加入队列，取出不断的进行松弛操作，直到队列为空  

    如果一个结点被加入队列超过n-1次，那么显然图中有负环  
*/


13.(Floyd-Warshall)弗洛伊德算法
/*
    |任意点对最短路算法|
    |求图中任意两点的最短距离的算法|
*/

for (int i = 0; i < n; i++) {   //  初始化为0  
    for (int j = 0; j < n; j++)  
        scanf("%lf", &dis[i][j]);  
}  

for (int k = 0; k < n; k++) {  
    for (int i = 0; i < n; i++) {  
        for (int j = 0; j < n; j++) {  
            dis[i][j] = min(dis[i][j], dis[i][k] + dis[k][j]);  
        }  
    }
}


二分图
14.染色法
//|交叉染色法判断二分图|

int bipartite(int s) {  
    int u, v;  
    queue<int>Q;  
    color[s] = 1;  
    Q.push(s);  
    while (!Q.empty()) {  
        u = Q.front();  
        Q.pop();  
        for (int i = 0; i < G[u].size(); i++) {  
            v = G[u][i];  
            if (color[v] == 0) {  
                color[v] = -color[u];  
                Q.push(v);  
            }  
            else if (color[v] == color[u])  
                return 0;  
        }  
    }  
    return 1;  
}  

15..匈牙利算法
/*
    |求解最大匹配问题|
    |递归实现|
*/

vector<int>G[maxn];  
bool inpath[maxn];  //  标记  
int match[maxn];    //  记录匹配对象  
void init()  
{  
    memset(match, -1, sizeof(match));  
    for (int i = 0; i < maxn; ++i) {  
        G[i].clear();  
    }  
}  
bool findpath(int k) {  
    for (int i = 0; i < G[k].size(); ++i) {  
        int v = G[k][i];  
        if (!inpath[v]) {  
            inpath[v] = true;  
            if (match[v] == -1 || findpath(match[v])) { // 递归  
                match[v] = k; // 即匹配对象是“k妹子”的  
                return true;  
            }  
        }  
    }  
    return false;  
}  

void hungary() {  
    int cnt = 0;  
    for (int i = 1; i <= m; i++) {  // m为需要匹配的“妹子”数  
        memset(inpath, false, sizeof(inpath)); // 每次都要初始化  
        if (findpath(i)) cnt++;  
    }  
    cout << cnt << endl;  
}  

/*
    |求解最大匹配问题|
    |dfs实现|
*/

int v1, v2;  
bool Map[501][501];  
bool visit[501];  
int link[501];  
int result;  

bool dfs(int x)  {  
    for (int y = 1; y <= v2; ++y)  {  
        if (Map[x][y] && !visit[y])  {  
            visit[y] = true;  
            if (link[y] == 0 || dfs(link[y]))  {  
                link[y] = x;  
                return true;  
            } 
		} 
	}  
    return false;  
}  


void Search()  {  
    for (int x = 1; x <= v1; x++)  {  
        memset(visit,false,sizeof(visit));  
        if (dfs(x))  
            result++;  
    }
}

动态规划
背包
16.17.18背包问题

/*
    |01背包|
    |完全背包|
    |多重背包|
*/

//  01背包：  

void bag01(int cost,int weight)  {  
    for(i = v; i >= cost; --i)  
    dp[i] = max(dp[i], dp[i-cost]+weight);  
}  

//  完全背包：  

void complete(int cost, int weight)  {  
    for(i = cost ; i <= v; ++i)  
    dp[i] = max(dp[i], dp[i - cost] + weight);  
}  

//  多重背包：  

void multiply(int cost, int weight, int amount)  {  
    if(cost * amount >= v)  
        complete(cost, weight);  
    else{  
        k = 1;  
        while (k < amount){  
            bag01(k * cost, k * weight);  
            amount -= k;  
            k += k;  
        }  
        bag01(cost * amount, weight * amount);  
    }  
}  


// other

int dp[1000000];
int c[55], m[110];
int sum;

void CompletePack(int c) {
    for (int v = c; v <= sum / 2; ++v){
        dp[v] = max(dp[v], dp[v - c] + c);
    }
}

void ZeroOnePack(int c) {
    for (int v = sum / 2; v >= c; --v) {
        dp[v] = max(dp[v], dp[v - c] + c);
    }
}

void multiplePack(int c, int m） {
    if (m * c > sum / 2)
        CompletePack(c);
    else{
        int k = 1;
        while (k < m){
            ZeroOnePack(k * c);
            m -= k;
            k <<= 1;
        }
        if (m != 0){
            ZeroOnePack(m * c);
        }
    }
}


19.最长上升子序列

/*
    |最长上升子序列|
    |状态转移|
*/

/*
    状态转移dp[i] = max{ 1.dp[j] + 1 };  j<i; a[j]<a[i];
    d[i]是以i结尾的最长上升子序列
    与i之前的 每个a[j]<a[i]的 j的位置的最长上升子序列+1后的值比较
*/

void solve(){   // 参考挑战程序设计入门经典;
    for(int i = 0; i < n; ++i){  
        dp[i] = 1;  
        for(int j = 0; j < i; ++j){  
            if(a[j] < a[i]){  
                dp[i] = max(dp[i], dp[j] + 1);  
            }
		} 
	}
}  

/* 
    优化方法：
    dp[i]表示长度为i+1的上升子序列的最末尾元素  
    找到第一个比dp末尾大的来代替 
*/

    void solve() {  
        for (int i = 0; i < n; ++i){
            dp[i] = INF;
        }
        for (int i = 0; i < n; ++i) {  
            *lower_bound(dp, dp + n, a[i]) = a[i];  //  返回一个指针  
        }  
        printf("%d\n", *lower_bound(dp, dp + n, INF) - dp;  
    }

/*  
    函数lower_bound()返回一个 iterator 它指向在[first,last)标记的有序序列中可以插入value，而不会破坏容器顺序的第一个位置，而这个位置标记了一个不小于value的值。
*/

20.最长公共子序列

/*
    |求最长公共子序列|
    |递推形式|
*/

void solve() {  
    for (int i = 0; i < n; ++i) {  
        for (int j = 0; j < m; ++j) {  
            if (s1[i] == s2[j]) {  
                dp[i + 1][j + 1] = dp[i][j] + 1;  
            }else {  
                dp[i + 1][j + 1] = max(dp[i][j + 1], dp[i + 1][j]);  
            } 
		} 
	}
}  

计算几何
21.向量基本用法

struct node {  
    double x; // 横坐标  
    double y; // 纵坐标  
};  

typedef node Vector;

Vector operator + (Vector A, Vector B) { return Vector(A.x + B.x, A.y + B.y); }  
Vector operator - (Point A, Point B) { return Vector(A.x - B.y, A.y - B.y); }  
Vector operator * (Vector A, double p) { return Vector(A.x*p, A.y*p); }  
Vector operator / (Vector A, double p) { return Vector(A.x / p, A.y*p); }  

double Dot(Vector A, Vector B) { return A.x*B.x + A.y*B.y; } // 向量点乘  
double Length(Vector A) { return sqrt(Dot(A, A)); }  // 向量模长  
double Angle(Vector A, Vector B) { return acos(Dot(A, B) / Length(A) / Length(B)); }  // 向量之间夹角  

double Cross(Vector A, Vector B) { // 叉积计算 公式  
    return A.x*B.y - A.y*B.x;  
}  

Vector Rotate(Vector A, double rad) // 向量旋转 公式  {  
    return Vector(A.x*cos(rad) - A.y*sin(rad), A.x*sin(rad) + A.y*cos(rad));  
}  

Point getLineIntersection(Point P, Vector v, Point Q, Vector w) { // 两直线交点t1 t2计算公式   
    Vector u = P - Q;   
    double t = Cross(w, u) / Cross(v, w);  // 求得是横坐标  
    return P + v*t;  // 返回一个点  
}  

22.求多边形面积

node G[maxn];  
int n;  

double Cross(node a, node b) { // 叉积计算  
    return a.x*b.y - a.y*b.x;  
}  

int main()  
{  
    while (scanf("%d", &n) != EOF && n) {  
        for (int i = 0; i < n; i++)   
            scanf("%lf %lf", &G[i].x, &G[i].y);  
        double sum = 0;  
        G[n].x = G[0].x;  
        G[n].y = G[0].y;  
        for (int i = 0; i < n; i++) {   
                sum += Cross(G[i], G[i + 1]);  
        }  
        // 或者  
            //for (int i = 0; i < n; i++) {  
                //sum += fun(G[i], G[（i + 1）% n]);  
            //}  
        sum = sum / 2.0;  
        printf("%.1f\n", sum);  
    }  
    system("pause");  
    return 0;  
}

23..判断线段相交

node P[35][105];     

double Cross_Prouct(node A,node B,node C) {     //  计算BA叉乘CA     
    return (B.x-A.x)*(C.y-A.y)-(B.y-A.y)*(C.x-A.x);      
}      
bool Intersect(node A,node B,node C,node D)  {  //  通过叉乘判断线段是否相交；           
    if(min(A.x,B.x)<=max(C.x,D.x)&&         //  快速排斥实验；      
       min(C.x,D.x)<=max(A.x,B.x)&&      
       min(A.y,B.y)<=max(C.y,D.y)&&      
       min(C.y,D.y)<=max(A.y,B.y)&&      
       Cross_Prouct(A,B,C)*Cross_Prouct(A,B,D)<0&&      //  跨立实验；      
       Cross_Prouct(C,D,A)*Cross_Prouct(C,D,B)<0)       //  叉乘异号表示在两侧；      
       return true;      
    else return false;      
}    

24.求三角形外心

Point circumcenter(const Point &a, const Point &b, const Point &c) { //返回三角形的外心        
    Point ret;  
    double a1 = b.x - a.x, b1 = b.y - a.y, c1 = (a1*a1 + b1*b1) / 2;  
    double a2 = c.x - a.x, b2 = c.y - a.y, c2 = (a2*a2 + b2*b2) / 2;  
    double d = a1*b2 - a2*b1;  
    ret.x = a.x + (c1*b2 - c2*b1) / d;  
    ret.y = a.y + (a1*c2 - a2*c1) / d;  
    return ret;  
}  

24.极角排序

double cross(point p1, point p2, point q1, point q2) {  // 叉积计算   
    return (q2.y - q1.y)*(p2.x - p1.x) - (q2.x - q1.x)*(p2.y - p1.y);  
}  
bool cmp(point a, point b)  {  
    point o;  
    o.x = o.y = 0;  
    return cross(o, b, o, a) < 0; // 叉积判断  
}  
sort(convex + 1, convex + cnt, cmp); // 按角排序, 从小到大 


#字符串
0.0查找子串在母串中的出现次数（简单版）
int find(char* a,char* b) {
	int cnt=0;
	for(int i=0;a[i];i++)
		for(int j=i,k=0;a[j]==b[k];j++,k++)
			if(b[k+1]=='\0') {
				cnt++;break;
			}
	return cnt;
}

0.1查找子串的位置（暴力匹配）
int ViolentMatch(char* s, char* p) {
	int sLen = strlen(s);
	int pLen = strlen(p);
 
	int i = 0,j = 0;
	while (i < sLen && j < pLen) {
		if (s[i] == p[j]) {
			//①如果当前字符匹配成功（即S[i] == P[j]），则i++，j++    
			i++;j++;
		}
		else {
			//②如果失配（即S[i]! = P[j]），令i = i - (j - 1)，j = 0    
			i = i - j + 1;
			j = 0;
		}
	}
	//匹配成功，返回模式串p在文本串s中的位置，否则返回-1
	return j == pLen ? i - j : -1;
}

//回溯改为kmp
int KmpSearch(char* s, char* p) {
	int i = 0,j = 0;
	int sLen = strlen(s),pLen = strlen(p);
	while (i < sLen && j < pLen) {
		//①如果j = -1，或者当前字符匹配成功（即S[i] == P[j]），都令i++，j++    
		if (j == -1 || s[i] == p[j]) {
			i++;
			j++;
		}
		else
			//②如果j != -1，且当前字符匹配失败（即S[i] != P[j]），则令 i 不变，j = next[j]    
			//next[j]即为j所对应的next值      
			j = next[j];
	}
	return j == pLen ? i - j : -1;
}


25.kmp

//next数组求法
void GetNext(char* p,int next[]) {
	int pLen = strlen(p);
	int j = 0,k = next[0] = -1;
	while (j < pLen-1) {
		//p[k]表示前缀，p[j]表示后缀
		if (k == -1 || p[k] == p[j]) {
			++k;++j;
			next[j] = k;
		}
		else k = next[k];
	}
}  

//优化过后的next 数组求法
void GetNextval(char* p, int next[]) {
	int pLen = strlen(p);
	next[0] = -1;
	int k = -1;
	int j = 0;
	while (j < pLen - 1) {
		//p[k]表示前缀，p[j]表示后缀  
		if (k == -1 || p[k] == p[j]) {
			++j;++k;
			//较之前next数组求法，改动在下面4行
			if (p[j] != p[k])
				next[j] = k;   //之前只有这一行
			else
				//因为不能出现p[j] = p[ next[j ]]，所以当出现时需要继续递归，k = next[k] = next[next[k]]
				next[j] = next[k];
		}
		else
			k = next[k];
	}
}



26.kmp扩展

#include<iostream>    
#include<cstring>    

using namespace std;

const int MM=100005;    

int next[MM],extand[MM];    
char S[MM],T[MM];    

void GetNext(const char *T) {    
    int len = strlen(T),a = 0;    
    next[0] = len;    
    while(a < len - 1 && T[a] == T[a + 1]) a++;    
    next[1] = a;    
    a = 1;    
    for(int k = 2; k < len; k ++) {    
        int p = a + next[a] - 1,L = next[k - a];    
        if( (k - 1) + L >= p) {    
            int j = (p - k + 1) > 0 ? (p - k + 1) : 0;    
            while(k + j < len && T[k + j] == T[j]) j++;    
            next[k] = j;    
            a = k;    
        }else next[k] = L;    
    }    
}    
void GetExtand(const char *S,const char *T) {    
    GetNext(T);    
    int slen = strlen(S),tlen = strlen(T),a = 0;    
    int MinLen = slen < tlen ? slen : tlen;    
    while(a < MinLen && S[a] == T[a]) a++;    
    extand[0] = a;     
    a = 0;    
    for(int k = 1; k < slen; k ++) {    
        int p = a + extand[a] - 1, L = next[k - a];    
        if( (k - 1) + L >= p) {    
            int j = (p - k + 1) > 0 ? (p - k + 1) : 0;    
            while(k + j < slen && j < tlen && S[k + j] == T[j]) j ++;    
            extand[k] = j;    
            a = k;    
        } else    
            extand[k] = L;    
    }    
}    
void show(const int *s,int len){    
    for(int i = 0; i < len; i ++)    
            cout << s[i] << ' ';    
    cout << endl;    
}    

int main() {    
    while(cin >> S >> T) {    
        GetExtand(S,T);    
        show(next,strlen(T));    
        show(extand,strlen(S));    
    }    
    return 0;    
}   


27.字典树

struct Trie{  
    int cnt;  
    Trie *next[maxn];  
    Trie(){  
        cnt = 0;  
        memset(next,0,sizeof(next));  
    }  
};  

Trie *root;  

void Insert(char *word)  {  
    Trie *tem = root;  
    while(*word != '\0')  {  
        int x = *word - 'a';  
        if(tem->next[x] == NULL)  
            tem->next[x] = new Trie;  
        tem = tem->next[x];  
        tem->cnt++;  
        word++;  
    }  
}  

int Search(char *word)  {  
    Trie *tem = root;  
    for(int i=0;word[i]!='\0';i++)  {  
        int x = word[i]-'a';  
        if(tem->next[x] == NULL)  
            return 0;  
        tem = tem->next[x];  
    }  
    return tem->cnt;  
}  

void Delete(char *word,int t) {  
    Trie *tem = root;  
    for(int i=0;word[i]!='\0';i++)  {  
        int x = word[i]-'a';  
        tem = tem->next[x];  
        (tem->cnt)-=t;  
    }  
    for(int i=0;i<maxn;i++)  
        tem->next[i] = NULL;  
}  

int main() {  
    int n;  
    char str1[50];  
    char str2[50];  
    while(scanf("%d",&n)!=EOF)  {  
        root = new Trie;  
        while(n--)  {  
            scanf("%s %s",str1,str2);  
            if(str1[0]=='i') {
                Insert(str2); 
            }else if(str1[0] == 's')  {  
                if(Search(str2))  
                    printf("Yes\n");  
                else  
                    printf("No\n");  
            }else  {  
                int t = Search(str2);  
                if(t)  
                    Delete(str2,t);  
            } } }  
    return 0;  
}  


28.AC自动机

#include<iostream>  
#include<cstdio>  
#include<cstring>  
#include<string>  

using namespace std;  

#define N 1000010  

char str[N], keyword[N];  
int head, tail;  

struct node {  
    node *fail;  
    node *next[26];  
    int count;  
    node() { //init  
        fail = NULL;// 默认为空  
        count = 0;  
        for(int i = 0; i < 26; ++i)  
            next[i] = NULL;  
    }  
}*q[N];  

node *root;  

void insert(char *str)  { // 建立Trie  
    int temp, len;  
    node *p = root;  
    len = strlen(str);  
    for(int i = 0; i < len; ++i)  {  
        temp = str[i] - 'a';  
        if(p->next[temp] == NULL)  
            p->next[temp] = new node();  
        p = p->next[temp];  
    }  
    p->count++;  
}  

void build_ac() { // 初始化fail指针，BFS 数组模拟队列：   
    q[tail++] = root;  
    while(head != tail)  {  
        node *p = q[head++]; // 弹出队头  
        node *temp = NULL;  
        for(int i = 0; i < 26; ++i)  {  
            if(p->next[i] != NULL)  {  
                if(p == root) { // 第一个元素fail必指向根  
                    p->next[i]->fail = root;
                }else {  
                    temp = p->fail; // 失败指针  
                    while(temp != NULL) { // 2种情况结束：匹配为空or找到匹配 
                        if(temp->next[i] != NULL) { // 找到匹配  
                            p->next[i]->fail = temp->next[i];  
                            break;  
                        }  
                        temp = temp->fail;  
                    }  
                    if(temp == NULL) // 为空则从头匹配  
                        p->next[i]->fail = root;  
                }  
                q[tail++] = p->next[i]; // 入队  
            }
		} 
	}  
}  

int query() // 扫描  
{  
    int index, len, result;  
    node *p = root; // Tire入口  
    result = 0;  
    len = strlen(str);  
    for(int i = 0; i < len; ++i)  
    {  
        index = str[i] - 'a';  
        while(p->next[index] == NULL && p != root) // 跳转失败指针  
            p = p->fail;  
        p = p->next[index];  
        if(p == NULL)  
            p = root;  
        node *temp = p; // p不动，temp计算后缀串  
        while(temp != root && temp->count != -1)   {  
            result += temp->count;  
            temp->count = -1;  
            temp = temp->fail;  
        }  
    }  
    return result;  
}  

int main() {  
    int num;  
    head= tail = 0;  
    root = new node();  
    scanf("%d", &num);  
    getchar();  
    for(int i = 0; i < num; ++i) {  
       scanf("%s",keyword);  
        insert(keyword);  
    }  
    build_ac();  
    scanf("%s", str);  
    if(query())  
        printf("YES\n");  
    else  
        printf("NO\n");  
    return 0;  
}  

/*
    假设有N个模式串，平均长度为L；文章长度为M。 建立Trie树：O(N*L) 建立fail指针：O(N*L) 模式匹配：O(M*L) 所以，总时间复杂度为:O( (N+M)*L )。
*/


#线段树
29.线段树 
1）点更新

struct node {
    int left, right;
    int max, sum;
};

node tree[maxn << 2];
int a[maxn];
int n;
int k = 1;
int p, q;
string str;

void build(int m, int l, int r) //m 是 树的标号{
    tree[m].left = l;
    tree[m].right = r;
    if (l == r) {
        tree[m].max = a[l];
        tree[m].sum = a[l];
        return;
    }
    int mid = (l + r) >> 1;
    build(m << 1, l, mid);
    build(m << 1 | 1, mid + 1, r);
    tree[m].max = max(tree[m << 1].max, tree[m << 1 | 1].max);
    tree[m].sum = tree[m << 1].sum + tree[m << 1 | 1].sum;
}

void update(int m, int a, int val) { //a 是 节点位置， val 是 更新的值（加减的值）
    if (tree[m].left == a && tree[m].right == a){
        tree[m].max += val;
        tree[m].sum += val;
        return;
    }
    int mid = (tree[m].left + tree[m].right) >> 1;
    if (a <= mid) 
        update(m << 1, a, val);
    else
        update(m << 1 | 1, a, val);
    tree[m].max = max(tree[m << 1].max, tree[m << 1 | 1].max);
    tree[m].sum = tree[m << 1].sum + tree[m << 1 | 1].sum;
}

int querySum(int m, int l, int r) {
    if (l == tree[m].left && r == tree[m].right)
        return tree[m].sum;
    
    int mid = (tree[m].left + tree[m].right) >> 1;
    if (r <= mid)
        return querySum(m << 1, l, r);
    else if (l > mid)
        return querySum(m << 1 | 1, l, r);
    return querySum(m << 1, l, mid) + querySum(m << 1 | 1, mid + 1, r);
}

int queryMax(int m, int l, int r) {
    if (l == tree[m].left && r == tree[m].right)
        return tree[m].max;
    int mid = (tree[m].left + tree[m].right) >> 1;
    if (r <= mid)
        return queryMax(m << 1, l, r);
    else if (l > mid)
        return queryMax(m << 1 | 1, l, r);
    return max(queryMax(m << 1, l, mid), queryMax(m << 1 | 1, mid + 1, r));
} 

build(1,1,n);  
update(1,a,b);  
query(1,a,b);  


2)区间更新

typedef long long ll;  
const int maxn = 100010;  

int t,n,q;  
ll anssum;  

struct node {  
    ll l,r;  
    ll addv,sum;  
}tree[maxn<<2];  

void maintain(int id) {  
    if(tree[id].l >= tree[id].r)  
        return ;  
    tree[id].sum = tree[id<<1].sum + tree[id<<1|1].sum;  
}  

void pushdown(int id) {  
    if(tree[id].l >= tree[id].r)  
        return ;  
    if(tree[id].addv) {  
        int tmp = tree[id].addv;  
        tree[id<<1].addv += tmp;  
        tree[id<<1|1].addv += tmp;  
        tree[id<<1].sum += (tree[id<<1].r - tree[id<<1].l + 1)*tmp;  
        tree[id<<1|1].sum += (tree[id<<1|1].r - tree[id<<1|1].l + 1)*tmp;  
        tree[id].addv = 0;  
    }  
}  

void build(int id,ll l,ll r) {  
    tree[id].l = l;  
    tree[id].r = r;  
    tree[id].addv = 0;  
    tree[id].sum = 0;  
    if(l==r)  {  
        tree[id].sum = 0;  
        return ;  
    }  
    ll mid = (l+r)>>1;  
    build(id<<1,l,mid);  
    build(id<<1|1,mid+1,r);  
    maintain(id);  
}  

void updateAdd(int id,ll l,ll r,ll val) {  
    if(tree[id].l >= l && tree[id].r <= r) {  
        tree[id].addv += val;  
        tree[id].sum += (tree[id].r - tree[id].l+1)*val;  
        return ;  
    }  
    pushdown(id);  
    ll mid = (tree[id].l+tree[id].r)>>1;  
    if(l <= mid)  
        updateAdd(id<<1,l,r,val);  
    if(mid < r)  
        updateAdd(id<<1|1,l,r,val);  
    maintain(id);  
}  

void query(int id,ll l,ll r) {  
    if(tree[id].l >= l && tree[id].r <= r){  
        anssum += tree[id].sum;  
        return ;  
    }  
    pushdown(id);  
    ll mid = (tree[id].l + tree[id].r)>>1;  
    if(l <= mid) query(id<<1,l,r);  
    if(mid < r) query(id<<1|1,l,r);  
    maintain(id);  
}  

int main() {  
    scanf("%d",&t);  
    int kase = 0 ;  
    while(t--){  
        scanf("%d %d",&n,&q);  
        build(1,1,n);  
        int id;  
        ll x,y;  
        ll val;  
        printf("Case %d:\n",++kase);  
        while(q--){  
            scanf("%d",&id);  
            if(id==0){  
                scanf("%lld %lld %lld",&x,&y,&val);  
                updateAdd(1,x+1,y+1,val);  
            }  
            else{  
                scanf("%lld %lld",&x,&y);  
                anssum = 0;  
                query(1,x+1,y+1);  
                printf("%lld\n",anssum);  
            } } }  
    return 0;  
}  


30.树状数组

#include<iostream>
#include<cstdio>
#include<cstring>
#include<string>
#include<cmath>

using namespace std;

typedef long long ll;

const int maxn = 50005;

int a[maxn];
int n;

int lowbit(const int t) {
    return t & (-t);
}

void insert(int t, int d) {
    while (t <= n){
        a[t] += d;
        t = t + lowbit(t);
    }
}

ll getSum(int t) {
    ll sum = 0;
    while (t > 0){
        sum += a[t];
        t = t - lowbit(t);
    }
    return sum;
}

int main() {
    int t, k, d;
    scanf("%d", &t);
    k= 1;
    while (t--){
        memset(a, 0, sizeof(a));
        scanf("%d", &n);
        for (int i = 1; i <= n; ++i) {
            scanf("%d", &d);
            insert(i, d);
        }
        string str;
        printf("Case %d:\n", k++);
        while (cin >> str) {
            if (str == "End")   break;
            int x, y;
            scanf("%d %d", &x, &y);
            if (str == "Query")
                printf("%lld\n", getSum(y) - getSum(x - 1));
            else if (str == "Add")
                insert(x, y);
            else if (str == "Sub")
                insert(x, -y);
        }
    }
    return 0;
}


#其他
31.中国剩余定理（孙子定理）

int CRT(int a[],int m[],int n) {    
    int M = 1;    
    int ans = 0;    
    for(int i=1; i<=n; i++)    
        M *= m[i];    
    for(int i=1; i<=n; i++) {    
        int x, y;    
        int Mi = M / m[i];    
        extend_Euclid(Mi, m[i], x, y);    
        ans = (ans + Mi * x * a[i]) % M;    
    }    
    if(ans < 0) ans += M;    
    return ans;    
}  

void extend_Euclid(int a, int b, int &x, int &y) {  
    if(b == 0) {  
        x = 1;  
        y = 0;  
        return;  
    }  
    extend_Euclid(b, a % b, x, y);  
    int tmp = x;  
    x = y;  
    y = tmp - (a / b) * y;  
}  