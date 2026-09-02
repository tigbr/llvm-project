// RUN: %clang_analyze_cc1 -analyzer-checker=optin.core.TaggedUnionChecker -fblocks -verify -analyzer-config eagerly-assume=false %s

struct tagged_union { // expected-warning{{inconsistently used tagged union type}}
	enum {
		kind1,
		kind2,
	} kind;
	union {
		struct {
			short x;
		} field1;
		struct {
			float x;
		} field2;
	} data;
};

void f(struct tagged_union t) {
	switch (t.kind) {
		case tagged_union::kind1: {
			t.data.field1.x = 1;
		} break;
		case tagged_union::kind2: {
			t.data.field2.x = 2.0f; // expected-note{{'kind2' matched with union field 'field2'}}
		} break;
	}
}

void g(struct tagged_union t) {
	switch (t.kind) {
		case tagged_union::kind1: {
			t.data.field1.x = 1;
		} break;
		case tagged_union::kind2: {
			t.data.field1.x = 2.0f; // expected-note{{'kind2' matched with union field 'field1'}}
		} break;
	}
}
