// RUN: %check_clang_tidy %s bugprone-union-ptr-cast-to-non-union-member-type-ptr %t

typedef short *short_ptr_typedef;

union MyUnion {
    short s;
    float f;
    short_ptr_typedef ptr1;
};

void always_allowed(union MyUnion *u) {
    (short*) u;
    (float*) u;
}

void option_dependent_default_behaviors(union MyUnion *u) {
    (void*) u;
    (char*) u;
    void *v = u;
    char *c = u;
}

void bad_implicit_casts(union MyUnion *u) {
    int    *p1 = u; // CHECK-MESSAGES: :[[@LINE]]:18: warning: the union pointed to by this expression has no field with the type 'int'
    long   *p2 = u; // CHECK-MESSAGES: :[[@LINE]]:18: warning: the union pointed to by this expression has no field with the type 'long'
    double *p3 = u; // CHECK-MESSAGES: :[[@LINE]]:18: warning: the union pointed to by this expression has no field with the type 'double'
    short_ptr_typedef p4 = u; // CHECK-MESSAGES: :[[@LINE]]:28: warning: the union pointed to by this expression has no field with the type 'short_ptr_typedef'
}

void bad_cstyle_casts(union MyUnion *u) {
    (long*) u;             // CHECK-MESSAGES: :[[@LINE]]:13: warning: the union pointed to by this expression has no field with the type 'long'
    (short_ptr_typedef) u; // CHECK-MESSAGES: :[[@LINE]]:25: warning: the union pointed to by this expression has no field with the type 'short_ptr_typedef'
}

void bad_cast_with_unknown_union_definition(union Unknown *u) {
    (char*)   u; // CHECK-MESSAGES: :[[@LINE]]:15: warning: the union pointed to by this expression has no field with the type 'char'
    (short*)  u; // CHECK-MESSAGES: :[[@LINE]]:15: warning: the union pointed to by this expression has no field with the type 'short'
    (int*)    u; // CHECK-MESSAGES: :[[@LINE]]:15: warning: the union pointed to by this expression has no field with the type 'int'
    (long*)   u; // CHECK-MESSAGES: :[[@LINE]]:15: warning: the union pointed to by this expression has no field with the type 'long'
    (float*)  u; // CHECK-MESSAGES: :[[@LINE]]:15: warning: the union pointed to by this expression has no field with the type 'float'
    (double*) u; // CHECK-MESSAGES: :[[@LINE]]:15: warning: the union pointed to by this expression has no field with the type 'double'
}

void irrelevant_casts(long i) {
	unsigned long ul = i;
	(unsigned long) i;
	void *v = (void*) i;
}
