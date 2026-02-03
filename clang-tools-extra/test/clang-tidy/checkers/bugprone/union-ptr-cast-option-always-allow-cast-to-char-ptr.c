// RUN: %check_clang_tidy %s bugprone-union-ptr-cast %t \
// RUN:   -config='{CheckOptions: { \
// RUN:     bugprone-union-ptr-cast.AlwaysAllowCastToCharPtr: false, \
// RUN:  }}' --

union MyUnion {
  short S;
  float F;
};

void optionDependentBehaviors(union MyUnion *U) {
  char *V1 = U; // CHECK-MESSAGES: :[[@LINE]]:14: warning: invalid cast from 'union MyUnion *' to 'char *'
  void *V2 = U;
  (char*) U; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union MyUnion *' to 'char *'
  (void*) U;
}
