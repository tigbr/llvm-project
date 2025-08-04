// RUN: %check_clang_tidy %s bugprone-union-ptr-cast-to-non-union-member-type-ptr %t

typedef short *short_ptr_typedef;

union {
    short s;
    float f;
    short_ptr_typedef ptr1;
} u;

void always_allowed() {
    (short*) &u;
    (float*) &u;
}

void option_dependent_default_behaviors() {
    (char*) &u;
    (void*) &u;
    void *v = &u;
}

void bad_cast_with_known_union_definition() {
    (long*) &u;             // CHECK-MESSAGES: :[[@LINE]]:5: warning: there is no member in this union with the same type as the cast's target pointer's pointee type
    (short_ptr_typedef) &u; // CHECK-MESSAGES: :[[@LINE]]:5: warning: there is no member in this union with the same type as the cast's target pointer's pointee type
}

union Unknown;

void bad_cast_with_unknown_union_definition(union Unknown *u) {
    (char*)   u; // CHECK-MESSAGES: :[[@LINE]]:15: warning: there is no member in this union with the same type as the cast's target pointer's pointee type
    (short*)  u; // CHECK-MESSAGES: :[[@LINE]]:15: warning: there is no member in this union with the same type as the cast's target pointer's pointee type
    (int*)    u; // CHECK-MESSAGES: :[[@LINE]]:15: warning: there is no member in this union with the same type as the cast's target pointer's pointee type
    (long*)   u; // CHECK-MESSAGES: :[[@LINE]]:15: warning: there is no member in this union with the same type as the cast's target pointer's pointee type
    (float*)  u; // CHECK-MESSAGES: :[[@LINE]]:15: warning: there is no member in this union with the same type as the cast's target pointer's pointee type
    (double*) u; // CHECK-MESSAGES: :[[@LINE]]:15: warning: there is no member in this union with the same type as the cast's target pointer's pointee type
}
