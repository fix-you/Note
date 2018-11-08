#include <bits/stdc++.h>
using namespace std;

typedef long long ll;
const int N = 1e5 + 15;

struct Edge{
	int u, v, nxt;
	int w;
};
Edge e[N<<2];
int head[N], ecnt, ans, flag;

void init(){
	memset(head,-1);
	ecnt = 0;
	ans = 0;
	flag = 0;
}

void _add( int u, int v, int w ){
	e[ecnt].u = u;
	e[ecnt].v = v;
	e[ecnt].w = w;
	e[ecnt].nxt = head[u];
	head[u] = ecnt ++;
}

void dfs( int u, int fa = 0, int c = 0, bool sta = 0 ){
	for ( int i = head[u]; i + 1; i = e[i].nxt ){
		int tmp = flag;
		int v = e[i].v;
		if ( v == fa ) continue;
		dfs( v, u, c + (e[i].w==0), (e[i].w==0) );
		if ( tmp != flag ) c = 0;
	}
	if ( c && sta ) ans ++, flag ++;
}

int main(){
	int n; scanf("%d", &n);
	init();
	for ( int i = 1; i < n; i ++ ){
		int u, v, w;
		scanf("%d%d%d", &u, &v, &w);
		_add( u, v, (w==1) );
		_add( v, u, (w==1) );
	}
	
	flag = 0;
	dfs(1);
	printf("%d\n", ans);
	return 0;
}