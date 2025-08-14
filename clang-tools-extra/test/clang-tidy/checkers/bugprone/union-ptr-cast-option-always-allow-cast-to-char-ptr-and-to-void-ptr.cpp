// RUN: %check_clang_tidy -std=c++98-or-later %s bugprone-union-ptr-cast %t \
// RUN:   -config='{CheckOptions: { \
// RUN:     bugprone-union-ptr-cast.AlwaysAllowCastToCharPtr: false, \
// RUN:     bugprone-union-ptr-cast.AlwaysAllowCastToVoidPtr: false, \
// RUN:  }}' --

union MyUnion {
  short S;
  float F;
};

void optionDependentBehaviors(union MyUnion *U) {
  void *V = U; // CHECK-MESSAGES: :[[@LINE]]:13: warning: the union pointed to by this expression has no field with the type 'void'
  (char*) U;   // CHECK-MESSAGES: :[[@LINE]]:11: warning: the union pointed to by this expression has no field with the type 'char'
  (void*) U;   // CHECK-MESSAGES: :[[@LINE]]:11: warning: the union pointed to by this expression has no field with the type 'void'

  reinterpret_cast<char*>(U); // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'char'
  reinterpret_cast<void*>(U); // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'void'
}
