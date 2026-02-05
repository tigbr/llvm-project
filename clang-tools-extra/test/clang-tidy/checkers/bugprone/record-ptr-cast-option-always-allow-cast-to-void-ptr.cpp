// RUN: %check_clang_tidy -std=c++98-or-later %s bugprone-record-ptr-cast %t \
// RUN:   -config='{CheckOptions: { \
// RUN:     bugprone-record-ptr-cast.AlwaysAllowCastToVoidPtr: false, \
// RUN:  }}'

union MyUnion {
  short S;
  float F;
};

void optionDependentBehaviors(union MyUnion *U) {
  void *V = U; // CHECK-MESSAGES: :[[@LINE]]:13: warning: invalid cast from 'union MyUnion *' to 'void *'
  (char*) U;
  (void*) U; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union MyUnion *' to 'void *'
  reinterpret_cast<char*>(U);
  reinterpret_cast<void*>(U); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union MyUnion *' to 'void *'
}
