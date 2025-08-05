// RUN: %check_clang_tidy -std=c++98-or-later %s bugprone-union-ptr-cast-to-non-union-member-type-ptr %t

typedef short *short_ptr_typedef;
using short_ptr_using = short*;

union MyUnion {
    short s;
    float f;
    short_ptr_typedef ptr1;
    short_ptr_using ptr2;
};

void always_allowed(union MyUnion *u) {
    (short*) u;
    (float*) u;
}

void option_dependent_default_behaviors(union MyUnion *u) {
    (void*) u;
    (char*) u;
    void *v = u;

    // Implicit casts like these are compile-time errors in C++
    // For this reason they are tested only in the C file.
    // char *c = u;
}

void bad_cast_with_known_union_definition(union MyUnion *u) {
    (long*) u;             // CHECK-MESSAGES: :[[@LINE]]:13: warning: the union pointed to by this expression has no field with the type 'long'
    (short_ptr_typedef) u; // CHECK-MESSAGES: :[[@LINE]]:25: warning: the union pointed to by this expression has no field with the type 'short_ptr_typedef'
    (short_ptr_using)   u; // CHECK-MESSAGES: :[[@LINE]]:25: warning: the union pointed to by this expression has no field with the type 'short_ptr_using'
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
