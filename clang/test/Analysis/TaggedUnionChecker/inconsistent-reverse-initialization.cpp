// RUN: %clang_analyze_cc1 -analyzer-checker=optin.core.TaggedUnionChecker -fblocks -verify -analyzer-config eagerly-assume=false %s

struct tagged_union { // expected-warning{{inconsistently used tagged union type}}
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
	t.data.field1 = 3; // expected-note{{'kind1' matched with union field 'field1'}}

	t.data.field2 = 10; // expected-note{{'kind1' matched with union field 'field2'}}
	t.kind = tagged_union::kind1;
}
