// RUN: %clang_analyze_cc1 -analyzer-checker=optin.core.TaggedUnionChecker -fblocks -verify -analyzer-config eagerly-assume=false %s

struct tagged_union { // expected-warning{{This tagged union type is inconsistently used}}
	enum {
		kind1,
		kind2,
	} kind;
	union {
		short field1;
		float field2;
	} data;
};

void f() {
	struct tagged_union t;

	t.kind = tagged_union::kind1;
	t.data.field1 = 3; // expected-note{{Here 'kind1' is matched with the union field 'field1'}}

	t.kind = tagged_union::kind1;
	t.data.field2 = 10; // expected-note{{Here 'kind1' is matched with the union field 'field2'}}
}
