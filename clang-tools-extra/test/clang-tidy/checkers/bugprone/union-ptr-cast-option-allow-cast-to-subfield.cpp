// RUN: %check_clang_tidy -std=c++98-or-later %s bugprone-union-ptr-cast %t \
// RUN:   --config='{CheckOptions: { \
// RUN:     bugprone-union-ptr-cast.AllowCastToSubField: false \
// RUN:  }}' -- \
// RUN: -isystem %S/Inputs/union-ptr-cast/system

typedef short *ShortPtrTypedef;

struct Bar {
  void *F1;
};

struct Foo {
  struct Bar F1;
  void **F2;
};

union FooBar {
  struct Foo F1;
  double **F2;
};

union MyUnion {
  volatile char *F1;
  const char *F2;
  const volatile char *F3;
  short F4;
  float F5;
  ShortPtrTypedef F6;
  union FooBar F7;
};

typedef union MyUnion TypedefMyUnion;
using UsingMyUnion = union MyUnion;

void test(union MyUnion *U, TypedefMyUnion *TU, UsingMyUnion *UU) {
  union FooBar *FB;
  (union FooBar*) U;
  (union FooBar*) TU;
  (union FooBar*) UU;

  struct Foo *SubFieldPtr1;
  (struct Foo*) U;   // CHECK-MESSAGES: :[[@LINE]]:17: warning: the union pointed to by this expression has no field with the type 'struct Foo'
  (struct Foo*) TU;  // CHECK-MESSAGES: :[[@LINE]]:17: warning: the union pointed to by this expression has no field with the type 'struct Foo'
  (struct Foo*) UU;  // CHECK-MESSAGES: :[[@LINE]]:17: warning: the union pointed to by this expression has no field with the type 'struct Foo'
  reinterpret_cast<struct Foo*>(U);  // CHECK-MESSAGES: :[[@LINE]]:33: warning: the union pointed to by this expression has no field with the type 'struct Foo'
  reinterpret_cast<struct Foo*>(TU); // CHECK-MESSAGES: :[[@LINE]]:33: warning: the union pointed to by this expression has no field with the type 'struct Foo'
  reinterpret_cast<struct Foo*>(UU); // CHECK-MESSAGES: :[[@LINE]]:33: warning: the union pointed to by this expression has no field with the type 'struct Foo'

  double ***SubFieldPtr2;
  (double***) U;     // CHECK-MESSAGES: :[[@LINE]]:15: warning: the union pointed to by this expression has no field with the type 'double **'
  (double***) TU;    // CHECK-MESSAGES: :[[@LINE]]:15: warning: the union pointed to by this expression has no field with the type 'double **'
  (double***) UU;    // CHECK-MESSAGES: :[[@LINE]]:15: warning: the union pointed to by this expression has no field with the type 'double **'
  reinterpret_cast<double***>(U);  // CHECK-MESSAGES: :[[@LINE]]:31: warning: the union pointed to by this expression has no field with the type 'double **'
  reinterpret_cast<double***>(TU); // CHECK-MESSAGES: :[[@LINE]]:31: warning: the union pointed to by this expression has no field with the type 'double **'
  reinterpret_cast<double***>(UU); // CHECK-MESSAGES: :[[@LINE]]:31: warning: the union pointed to by this expression has no field with the type 'double **'

  struct Bar *SubFieldPtr3;
  (struct Bar*) U;   // CHECK-MESSAGES: :[[@LINE]]:17: warning: the union pointed to by this expression has no field with the type 'struct Bar'
  (struct Bar*) TU;  // CHECK-MESSAGES: :[[@LINE]]:17: warning: the union pointed to by this expression has no field with the type 'struct Bar'
  (struct Bar*) UU;  // CHECK-MESSAGES: :[[@LINE]]:17: warning: the union pointed to by this expression has no field with the type 'struct Bar'
  reinterpret_cast<struct Bar*>(U);  // CHECK-MESSAGES: :[[@LINE]]:33: warning: the union pointed to by this expression has no field with the type 'struct Bar'
  reinterpret_cast<struct Bar*>(TU); // CHECK-MESSAGES: :[[@LINE]]:33: warning: the union pointed to by this expression has no field with the type 'struct Bar'
  reinterpret_cast<struct Bar*>(UU); // CHECK-MESSAGES: :[[@LINE]]:33: warning: the union pointed to by this expression has no field with the type 'struct Bar'

  void ***SubFieldPtr4;
  (void ***) U;      // CHECK-MESSAGES: :[[@LINE]]:14: warning: the union pointed to by this expression has no field with the type 'void **'
  (void ***) TU;     // CHECK-MESSAGES: :[[@LINE]]:14: warning: the union pointed to by this expression has no field with the type 'void **'
  (void ***) UU;     // CHECK-MESSAGES: :[[@LINE]]:14: warning: the union pointed to by this expression has no field with the type 'void **'
  reinterpret_cast<void ***>(U);  // CHECK-MESSAGES: :[[@LINE]]:30: warning: the union pointed to by this expression has no field with the type 'void **'
  reinterpret_cast<void ***>(TU); // CHECK-MESSAGES: :[[@LINE]]:30: warning: the union pointed to by this expression has no field with the type 'void **'
  reinterpret_cast<void ***>(UU); // CHECK-MESSAGES: :[[@LINE]]:30: warning: the union pointed to by this expression has no field with the type 'void **'

  void **SubFieldPtr5;
  (void **) U;       // CHECK-MESSAGES: :[[@LINE]]:13: warning: the union pointed to by this expression has no field with the type 'void *'
  (void **) TU;      // CHECK-MESSAGES: :[[@LINE]]:13: warning: the union pointed to by this expression has no field with the type 'void *'
  (void **) UU;      // CHECK-MESSAGES: :[[@LINE]]:13: warning: the union pointed to by this expression has no field with the type 'void *'
  reinterpret_cast<void **>(U);  // CHECK-MESSAGES: :[[@LINE]]:29: warning: the union pointed to by this expression has no field with the type 'void *'
  reinterpret_cast<void **>(TU); // CHECK-MESSAGES: :[[@LINE]]:29: warning: the union pointed to by this expression has no field with the type 'void *'
  reinterpret_cast<void **>(UU); // CHECK-MESSAGES: :[[@LINE]]:29: warning: the union pointed to by this expression has no field with the type 'void *'
}
