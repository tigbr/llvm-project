// RUN: %check_clang_tidy %s bugprone-union-ptr-cast %t \
// RUN:   -config='{CheckOptions: { \
// RUN:     bugprone-union-ptr-cast.AlwaysAllowCastToCharPtr: false, \
// RUN:     bugprone-union-ptr-cast.AlwaysAllowCastToVoidPtr: false, \
// RUN:  }}' --

union MyUnion {
  short S;
  float F;
};

void option_dependent_behaviors(union MyUnion *U) {
  char *V1 = U; // CHECK-MESSAGES: :[[@LINE]]:14: warning: the union pointed to by this expression has no field with the type 'char'
  void *V2 = U; // CHECK-MESSAGES: :[[@LINE]]:14: warning: the union pointed to by this expression has no field with the type 'void'
  (char*) U; // CHECK-MESSAGES: :[[@LINE]]:11: warning: the union pointed to by this expression has no field with the type 'char'
  (void*) U; // CHECK-MESSAGES: :[[@LINE]]:11: warning: the union pointed to by this expression has no field with the type 'void'
}
