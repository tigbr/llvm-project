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
    (char*) u;
    (void*) u;
    void *v = u;
}

// Implicit casts like (short *p = &my_union;) are compile-time errors in C++
// For this reason these cases are present only in the C language test file.

void bad_cast_with_known_union_definition(union MyUnion *u) {
    (long*) u;             // CHECK-MESSAGES: :[[@LINE]]:13: warning: the union pointed to by '&u' has no field with the type 'long'
    // (short_ptr_typedef) u; // CHECK-MESSAGES: :[[@LINE]]:25: warning: there is no member in this union with the same type as the cast's target pointer's pointee type
    // (short_ptr_using)   u; // CHECK-MESSAGES: :[[@LINE]]:25: warning: there is no member in this union with the same type as the cast's target pointer's pointee type
}

void bad_cast_with_unknown_union_definition(union Unknown *a) {
    // (char*)   a; // CHECK-MESSAGES: :[[@LINE]]:15: warning: there is no member in this union with the same type as the cast's target pointer's pointee type
    // (short*)  a; // CHECK-MESSAGES: :[[@LINE]]:15: warning: there is no member in this union with the same type as the cast's target pointer's pointee type
    // (int*)    a; // CHECK-MESSAGES: :[[@LINE]]:15: warning: there is no member in this union with the same type as the cast's target pointer's pointee type
    // (long*)   a; // CHECK-MESSAGES: :[[@LINE]]:15: warning: there is no member in this union with the same type as the cast's target pointer's pointee type
    // (float*)  a; // CHECK-MESSAGES: :[[@LINE]]:15: warning: there is no member in this union with the same type as the cast's target pointer's pointee type
    // (double*) a; // CHECK-MESSAGES: :[[@LINE]]:15: warning: there is no member in this union with the same type as the cast's target pointer's pointee type
}
