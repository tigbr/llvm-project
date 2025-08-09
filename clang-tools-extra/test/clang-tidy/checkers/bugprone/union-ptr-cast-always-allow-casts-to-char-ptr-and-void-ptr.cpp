// RUN: %check_clang_tidy -std=c++98-or-later %s bugprone-union-ptr-cast-to-non-union-member-type-ptr %t \
// RUN:   -config='{CheckOptions: { \
// RUN:     bugprone-union-ptr-cast-to-non-union-member-type-ptr.AlwaysAllowCastToPtrToChar: false, \
// RUN:     bugprone-union-ptr-cast-to-non-union-member-type-ptr.AlwaysAllowCastToPtrToVoid: false, \
// RUN:  }}' --

union MyUnion {
    short s;
    float f;
};

void option_dependent_behaviors(union MyUnion *u) {
    void *v = u; // CHECK-MESSAGES: :[[@LINE]]:15: warning: the union pointed to by this expression has no field with the type 'void'
    (char*) u;   // CHECK-MESSAGES: :[[@LINE]]:13: warning: the union pointed to by this expression has no field with the type 'char'
    (void*) u;   // CHECK-MESSAGES: :[[@LINE]]:13: warning: the union pointed to by this expression has no field with the type 'void'

    reinterpret_cast<char*>(u); // CHECK-MESSAGES: :[[@LINE]]:29: warning: the union pointed to by this expression has no field with the type 'char'
    reinterpret_cast<void*>(u); // CHECK-MESSAGES: :[[@LINE]]:29: warning: the union pointed to by this expression has no field with the type 'void'
}
