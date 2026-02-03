// RUN: %check_clang_tidy -std=c++98-or-later %s bugprone-union-ptr-cast %t \
// RUN:   -config='{CheckOptions: { \
// RUN:     bugprone-union-ptr-cast.AlwaysAllowCastToCharPtr: false, \
// RUN:  }}' --

union MyUnion {
  short S;
  float F;
};

void optionDependentBehaviors(union MyUnion *U) {
  void *V = U;
  (char*) U; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union MyUnion *' to 'char *'
  (void*) U;

  reinterpret_cast<char*>(U); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union MyUnion *' to 'char *'
  reinterpret_cast<void*>(U);
}
