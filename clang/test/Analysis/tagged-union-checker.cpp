// RUN: %clang_analyze_cc1 -analyzer-checker=core,debug.ExprInspection -fblocks -verify -analyzer-config eagerly-assume=false %s

enum tag_values {
	tag1,
	tag2,
	tag3,
};

struct bar {
	enum tag_values type;
	union {
		char c;
		short s;
		int i;
		long l;
	} data;
};

void foo(tag_values tag) {
    // expected-warning@+1 {{"Inconsistent tagged union access!"}}
    switch (tag) {
		case tag1: break;
		case tag2: break;
		case tag3: break;
	}
}

int main(int argc, char **argv) {
	struct bar a;

	a.type = tag3;
	a.data.s = 43;

	a.data.s = 44;
	return 0;
}
