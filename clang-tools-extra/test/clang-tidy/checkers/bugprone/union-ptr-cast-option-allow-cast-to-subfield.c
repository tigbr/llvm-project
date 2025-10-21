// RUN: %check_clang_tidy %s bugprone-union-ptr-cast %t \
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

void test(union MyUnion *U, TypedefMyUnion *TU) {
  union FooBar *FB;
  FB = U;
  FB = TU;
  (union FooBar*) U;
  (union FooBar*) TU;

  struct Foo *SubFieldPtr1;
  SubFieldPtr1 = U;  // CHECK-MESSAGES: :[[@LINE]]:18: warning: the union pointed to by this expression has no field with the type 'struct Foo'
  SubFieldPtr1 = TU; // CHECK-MESSAGES: :[[@LINE]]:18: warning: the union pointed to by this expression has no field with the type 'struct Foo'
  (struct Foo*) U;   // CHECK-MESSAGES: :[[@LINE]]:17: warning: the union pointed to by this expression has no field with the type 'struct Foo'
  (struct Foo*) TU;  // CHECK-MESSAGES: :[[@LINE]]:17: warning: the union pointed to by this expression has no field with the type 'struct Foo'

  double ***SubFieldPtr2;
  SubFieldPtr2 = U;  // CHECK-MESSAGES: :[[@LINE]]:18: warning: the union pointed to by this expression has no field with the type 'double **'
  SubFieldPtr2 = TU; // CHECK-MESSAGES: :[[@LINE]]:18: warning: the union pointed to by this expression has no field with the type 'double **'
  (double***) U;     // CHECK-MESSAGES: :[[@LINE]]:15: warning: the union pointed to by this expression has no field with the type 'double **'
  (double***) TU;    // CHECK-MESSAGES: :[[@LINE]]:15: warning: the union pointed to by this expression has no field with the type 'double **'

  struct Bar *SubFieldPtr3;
  SubFieldPtr3 = U;  // CHECK-MESSAGES: :[[@LINE]]:18: warning: the union pointed to by this expression has no field with the type 'struct Bar'
  SubFieldPtr3 = TU; // CHECK-MESSAGES: :[[@LINE]]:18: warning: the union pointed to by this expression has no field with the type 'struct Bar'
  (struct Bar*) U;   // CHECK-MESSAGES: :[[@LINE]]:17: warning: the union pointed to by this expression has no field with the type 'struct Bar'
  (struct Bar*) TU;  // CHECK-MESSAGES: :[[@LINE]]:17: warning: the union pointed to by this expression has no field with the type 'struct Bar'

  void ***SubFieldPtr4;
  SubFieldPtr4 = U;  // CHECK-MESSAGES: :[[@LINE]]:18: warning: the union pointed to by this expression has no field with the type 'void **'
  SubFieldPtr4 = TU; // CHECK-MESSAGES: :[[@LINE]]:18: warning: the union pointed to by this expression has no field with the type 'void **'
  (void ***) U;      // CHECK-MESSAGES: :[[@LINE]]:14: warning: the union pointed to by this expression has no field with the type 'void **'
  (void ***) TU;     // CHECK-MESSAGES: :[[@LINE]]:14: warning: the union pointed to by this expression has no field with the type 'void **'

  void **SubFieldPtr5;
  SubFieldPtr5 = U;  // CHECK-MESSAGES: :[[@LINE]]:18: warning: the union pointed to by this expression has no field with the type 'void *'
  SubFieldPtr5 = TU; // CHECK-MESSAGES: :[[@LINE]]:18: warning: the union pointed to by this expression has no field with the type 'void *'
  (void **) U;       // CHECK-MESSAGES: :[[@LINE]]:13: warning: the union pointed to by this expression has no field with the type 'void *'
  (void **) TU;      // CHECK-MESSAGES: :[[@LINE]]:13: warning: the union pointed to by this expression has no field with the type 'void *'
}
