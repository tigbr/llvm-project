// RUN: %clang_analyze_cc1 -analyzer-checker=core,debug.ExprInspection -fblocks -verify -analyzer-config eagerly-assume=false %s

enum tag_values {
	t1,
	t2,
	t3,
};

struct bar {
	enum tag_values type;
	union {
		char d1;
		short d2;
		int d3;
		long d4;
	} data;
};

void foo(tag_values tag) {
    // expected-warning@+1 {{"Inconsistent tagged union access!"}}
    // switch (tag) {
	// 	case t1: break;
	// 	case t2: break;
	// 	case t3: break;
	// }
}

int main(int argc, char **argv) {
	struct bar a;

	// Ezt hogyan lenne jó kezelni?
	// Elvileg tetszőleges sorrendben is be lehet állítani az unió és az enum értékét.
	// a.data.d1 = 1;
	// a.type = t1;

	a.type = t1;
	a.data.d1 = 1;

	// a.type = t2;
	a.data.d2 = 1;

	// a.data.d3 = 1;

	// switch (a.type) {
	// 	case t1: a.data.d1 = 1; break;
	// 	case t2: a.data.d2 = 1; break;
	// 	case t3: a.data.d3 = 1; break;
	// }

	// a.type = t1;
	// a.type = t2;

	// if (a.type == t1) {

	// }

	return 0;
}

