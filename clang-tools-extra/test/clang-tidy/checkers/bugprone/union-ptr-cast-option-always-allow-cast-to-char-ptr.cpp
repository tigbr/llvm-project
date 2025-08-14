// RUN: %check_clang_tidy -std=c++98-or-later %s bugprone-union-ptr-cast %t \
// RUN:   -config='{CheckOptions: { \
// RUN:     bugprone-union-ptr-cast.AlwaysAllowCastToCharPtr: false, \
// RUN:  }}' --

union MyUnion {
    short s;
    float f;
};

void option_dependent_behaviors(union MyUnion *U) {
    void *V = U;
    (char*) U;   // CHECK-MESSAGES: :[[@LINE]]:13: warning: the union pointed to by this expression has no field with the type 'char'
    (void*) U;

    reinterpret_cast<char*>(U); // CHECK-MESSAGES: :[[@LINE]]:29: warning: the union pointed to by this expression has no field with the type 'char'
    reinterpret_cast<void*>(U);
}
