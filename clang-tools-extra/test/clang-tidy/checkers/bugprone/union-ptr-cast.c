// RUN: %check_clang_tidy %s bugprone-union-ptr-cast-to-non-union-member-type-ptr %t

typedef short *short_ptr_typedef;

union MyUnion {
    short s;
    float f;
    short_ptr_typedef spt;
};

void always_allowed(union MyUnion *u) {
    short *s = u;
    float *f = u;
    short_ptr_typedef *spt = u;

    (short*) u;
    (float*) u;
    (short_ptr_typedef*) u;
}

void option_dependent_default_behaviors(union MyUnion *u) {
    char *c = u;
    void *v = u;
    (char*) u;
    (void*) u;
}

void bad_implicit_casts(union MyUnion *u) {
    int    *p1 = u; // CHECK-MESSAGES: :[[@LINE]]:18: warning: the union pointed to by this expression has no field with the type 'int'
    long   *p2 = u; // CHECK-MESSAGES: :[[@LINE]]:18: warning: the union pointed to by this expression has no field with the type 'long'
    double *p3 = u; // CHECK-MESSAGES: :[[@LINE]]:18: warning: the union pointed to by this expression has no field with the type 'double'
    short_ptr_typedef p4 = u; // CHECK-MESSAGES: :[[@LINE]]:28: warning: the union pointed to by this expression has no field with the type 'short_ptr_typedef'
}

void bad_cstyle_casts(union MyUnion *u) {
    (long*) u;             // CHECK-MESSAGES: :[[@LINE]]:13: warning: the union pointed to by this expression has no field with the type 'long'

    // It does not matter that the union has a field with the same type
    // as the aliased type. Typedefs and usings are not considered "transparent"
    // in that sense.
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

void casts_that_should_not_be_analyzed(long i) {
	long li;
	unsigned long ul = li;
	(unsigned long) li;
    (void*) li;
}
