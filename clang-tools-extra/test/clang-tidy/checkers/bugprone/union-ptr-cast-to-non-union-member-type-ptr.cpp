// RUN: %check_clang_tidy %s bugprone-union-ptr-cast-to-non-union-member-type-ptr %t

typedef short *short_ptr_typedef;
using short_ptr_using = short*;

union {
    short s;
    float f;
    short_ptr_typedef ptr1;
    short_ptr_using ptr2;
} u;

void always_allowed() {
    (short*) &u;
    (float*) &u;
}

void option_dependent_defaults() {
    (char*) &u;
    (void*) &u;
    void *v = &u;
}

void bad_cast_with_known_union_definition(union unknown *ptr_to_unknown) {
    (long*) &u;             // CHECK-MESSAGES: :[[@LINE]]:5: warning: bad
    (short_ptr_typedef) &u; // CHECK-MESSAGES: :[[@LINE]]:5: warning: bad
    (short_ptr_using)   &u; // CHECK-MESSAGES: :[[@LINE]]:5: warning: bad
}

void bad_cast_with_unknown_union_definition(union unknown *ptr_to_unknown) {
    (char*)   ptr_to_unknown; // CHECK-MESSAGES: :[[@LINE]]:15: warning: bad
    (short*)  ptr_to_unknown; // CHECK-MESSAGES: :[[@LINE]]:15: warning: bad
    (int*)    ptr_to_unknown; // CHECK-MESSAGES: :[[@LINE]]:15: warning: bad
    (long*)   ptr_to_unknown; // CHECK-MESSAGES: :[[@LINE]]:15: warning: bad
    (float*)  ptr_to_unknown; // CHECK-MESSAGES: :[[@LINE]]:15: warning: bad
    (double*) ptr_to_unknown; // CHECK-MESSAGES: :[[@LINE]]:15: warning: bad
}
