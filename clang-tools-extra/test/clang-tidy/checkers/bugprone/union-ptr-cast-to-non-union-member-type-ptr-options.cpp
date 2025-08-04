// RUN: %check_clang_tidy -std=c++98-or-later %s bugprone-union-ptr-cast-to-non-union-member-type-ptr %t \
// RUN:   -config='{CheckOptions: { \
// RUN:     bugprone-union-ptr-cast-to-non-union-member-type-ptr.AllowCastToPtrToChar: false, \
// RUN:     bugprone-union-ptr-cast-to-non-union-member-type-ptr.AllowCastToPtrToVoid: false, \
// RUN:  }}' --

union {
    short s;
    float f;
} u;

void option_dependent_defaults() {
    (char*) &u;   // CHECK-MESSAGES: :[[@LINE]]:5: warning: there is no member in this union with the same type as the cast's target pointer's pointee type
    (void*) &u;   // CHECK-MESSAGES: :[[@LINE]]:13: warning: there is no member in this union with the same type as the cast's target pointer's pointee type
    void *v = &u; // CHECK-MESSAGES: :[[@LINE]]:15: warning: there is no member in this union with the same type as the cast's target pointer's pointee type
}
