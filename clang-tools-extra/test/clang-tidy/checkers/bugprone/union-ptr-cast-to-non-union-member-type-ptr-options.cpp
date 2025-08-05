// RUN: %check_clang_tidy -std=c++98-or-later %s bugprone-union-ptr-cast-to-non-union-member-type-ptr %t \
// RUN:   -config='{CheckOptions: { \
// RUN:     bugprone-union-ptr-cast-to-non-union-member-type-ptr.AllowCastToPtrToChar: false, \
// RUN:     bugprone-union-ptr-cast-to-non-union-member-type-ptr.AllowCastToPtrToVoid: false, \
// RUN:  }}' --

union MyUnion {
    short s;
    float f;
};

void option_dependent_behaviors(union MyUnion *u) {
    (char*) u;   // CHECK-MESSAGES: :[[@LINE]]:13: warning: the union pointed to by this expression has no field with the type 'char'
    (void*) u;   // CHECK-MESSAGES: :[[@LINE]]:13: warning: the union pointed to by this expression has no field with the type 'void'
    void *v = u; // CHECK-MESSAGES: :[[@LINE]]:15: warning: the union pointed to by this expression has no field with the type 'void'
}

void irrelevant_casts(long i) {
	unsigned long ul = i;
	(unsigned long) i;
	void *v = (void*) i;
}
