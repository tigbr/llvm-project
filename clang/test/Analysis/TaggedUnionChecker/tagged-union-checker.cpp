// RUN: %clang_analyze_cc1 -analyzer-checker=optin.core.TaggedUnionChecker -fblocks -verify -analyzer-config eagerly-assume=false %s

struct tagged_union {
	enum {
		kind1,
		kind2,
	} kind;
	union {
		short field1;
		float field2;
	}  data;
};

void f(struct tagged_union t) {
	switch (t.kind) {
		case tagged_union::kind1: {
			t.data.field1 = 1;
		} break;
		case tagged_union::kind2: {
			t.data.field2 = 2.0f;
		} break;
	}
}

void g(struct tagged_union t) {
	switch (t.kind) {
		case tagged_union::kind1: {
			t.data.field1 = 1;
		} break;
		case tagged_union::kind2: {
			t.data.field2 = 2.0f;
		} break;
	}
}
