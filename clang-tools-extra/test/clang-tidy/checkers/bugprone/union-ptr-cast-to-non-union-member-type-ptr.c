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
    (char*) u;
    (void*) u;
    void *v = u;
}

void bad_implicit_casts(union MyUnion *u) {
    // short  *p1 = u; // CHECK-MESSAGES: :[[@LINE]]:15: warning: there is no member in this union with the same type as the cast's target pointer's pointee type
    // int    *p2 = u; // CHECK-MESSAGES: :[[@LINE]]:15: warning: there is no member in this union with the same type as the cast's target pointer's pointee type
    // long   *p3 = u; // CHECK-MESSAGES: :[[@LINE]]:15: warning: there is no member in this union with the same type as the cast's target pointer's pointee type
    // float  *p4 = u; // CHECK-MESSAGES: :[[@LINE]]:15: warning: there is no member in this union with the same type as the cast's target pointer's pointee type
    // double *p5 = u; // CHECK-MESSAGES: :[[@LINE]]:15: warning: there is no member in this union with the same type as the cast's target pointer's pointee type
}

void bad_cstyle_casts(union MyUnion *u) {
    // (long*) &u;             // CHECK-MESSAGES: :[[@LINE]]:5: warning: there is no member in this union with the same type as the cast's target pointer's pointee type
    // (short_ptr_typedef) &u; // CHECK-MESSAGES: :[[@LINE]]:5: warning: there is no member in this union with the same type as the cast's target pointer's pointee type
}

void bad_cast_with_unknown_union_definition(union Unknown *u) {
    // (char*)   u; // CHECK-MESSAGES: :[[@LINE]]:15: warning: there is no member in this union with the same type as the cast's target pointer's pointee type
    // (short*)  u; // CHECK-MESSAGES: :[[@LINE]]:15: warning: there is no member in this union with the same type as the cast's target pointer's pointee type
    // (int*)    u; // CHECK-MESSAGES: :[[@LINE]]:15: warning: there is no member in this union with the same type as the cast's target pointer's pointee type
    // (long*)   u; // CHECK-MESSAGES: :[[@LINE]]:15: warning: there is no member in this union with the same type as the cast's target pointer's pointee type
    // (float*)  u; // CHECK-MESSAGES: :[[@LINE]]:15: warning: there is no member in this union with the same type as the cast's target pointer's pointee type
    // (double*) u; // CHECK-MESSAGES: :[[@LINE]]:15: warning: there is no member in this union with the same type as the cast's target pointer's pointee type
}
