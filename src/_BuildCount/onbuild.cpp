#include <fstream>
using namespace std;
int main() {
	fstream i, o;
	i.open("build_count.txt", ios::in);
	int cnt;
	i >> cnt;
	i.close();
	o.open("build_count.txt", ios::out);
	cnt++;
	o << cnt;
	o.close();
	if(i.bad() || o.bad()) return 1;
	return 0;
}
