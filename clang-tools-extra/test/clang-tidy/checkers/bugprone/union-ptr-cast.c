// RUN: %check_clang_tidy %s bugprone-union-ptr-cast %t -- -- \
// RUN: -isystem %S/Inputs/union-ptr-cast/system

typedef short *ShortPtrTypedef;
typedef ShortPtrTypedef ShortPtrTypedefTypedef;
typedef ShortPtrTypedef *ShortPtrTypedefPtr;
typedef long *LongPtrTypedef;

typedef float *FloatPtrTypedef;
typedef FloatPtrTypedef *FloatPtrTypedefPtrTypedef;

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

void castToTypeInUnion(union MyUnion *U, TypedefMyUnion *TU) {
  volatile char *V1;
  V1 = U;
  V1 = TU;

  const char *V2;
  V2 = U;
  V2 = TU;

  const volatile char *V3;
  V3 = U;
  V3 = TU;

  short *V4;
  V4 = U;
  V4 = TU;

  float *V5;
  V5 = U;
  V5 = TU;

  ShortPtrTypedef *V6;
  V6 = U;
  V6 = TU;

  ShortPtrTypedef V7;
  V7 = U;
  V7 = TU;

  ShortPtrTypedefTypedef V8;
  V8 = U;
  V8 = TU;

  union FooBar *V9;
  V9 = U;
  V9 = TU;

  (volatile char**) U;
  (volatile char**) TU;
  (const char**) U;
  (const char**) TU;
  (const volatile char**) U;
  (const volatile char**) TU;
  (short*) U;
  (short*) TU;
  (float*) U;
  (float*) TU;
  (ShortPtrTypedef*) U;
  (ShortPtrTypedef*) TU;
  (ShortPtrTypedef) U;
  (ShortPtrTypedef) TU;
  (ShortPtrTypedefTypedef) U;
  (ShortPtrTypedefTypedef) TU;
  (union FooBar*) U;
  (union FooBar*) TU;
}

#include <pthread.h>

void optionDependentDefaultBehaviors(union MyUnion *U, TypedefMyUnion *TU) {
  /* AllowCastToCharPtr */
  char *C;
  C = U;
  C = TU;
  (char*) U;
  (char*) TU;

  /* AllowCastToVoidPtr */
  void *V = U;
  V = TU;
  (void*) U;
  (void*) TU;

  /* AllowCastToSubField */
  struct Foo *SubFieldPtr1;
  SubFieldPtr1 = U;
  SubFieldPtr1 = TU;
  (struct Foo*) U;
  (struct Foo*) TU;

  double ***SubFieldPtr2;
  SubFieldPtr2 = U;
  SubFieldPtr2 = TU;
  (double***) U;
  (double***) TU;

  struct Bar *SubFieldPtr3;
  SubFieldPtr3 = U;
  SubFieldPtr3 = TU;
  (struct Bar*) U;
  (struct Bar*) TU;

  void ***SubFieldPtr4;
  SubFieldPtr4 = U;  // CHECK-MESSAGES: :[[@LINE]]:18: warning: the union pointed to by this expression has no field with the type 'void **'
  SubFieldPtr4 = TU; // CHECK-MESSAGES: :[[@LINE]]:18: warning: the union pointed to by this expression has no field with the type 'void **'
  (void ***) U;      // CHECK-MESSAGES: :[[@LINE]]:14: warning: the union pointed to by this expression has no field with the type 'void **'
  (void ***) TU;     // CHECK-MESSAGES: :[[@LINE]]:14: warning: the union pointed to by this expression has no field with the type 'void **'

  void **SubFieldPtr5;
  SubFieldPtr5 = U;
  SubFieldPtr5 = TU;
  (void **) U;
  (void **) TU;

  /* IgnoreIfUnionIsFromSystemHeader */
  // By default, do not analyze cast expressions where the pointee union
  // comes from from a system header file. C has no namespaces, so that
  // is omitted from this file.
  pthread_mutex_t *T;
  void *P = T;
  (void*) T;
}

void irrelevantCastExpressions(union MyUnion *U, TypedefMyUnion *TU) {
  long LI;
  unsigned long UL = LI;
  (unsigned long) LI;
  (void*) LI;

  union MyUnion *MU = U;
  (union MyUnion*) U;

  TypedefMyUnion *MTU = TU;
  (TypedefMyUnion*) TU;
}

void castsWithQualifierMismatches() {
  typedef union { char *Ptr; } TypedefU1;
  TypedefU1 *TU1;
  union { char *Ptr; }   *U1;
  (volatile char**)       U1; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'volatile char *'
  (const char**)          U1; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'const char *'
  (const volatile char**) U1; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'const volatile char *'
  volatile char       **U1_V1 = U1; // CHECK-MESSAGES: :[[@LINE]]:33: warning: the union pointed to by this expression has no field with the type 'volatile char *'
  const char          **U1_V2 = U1; // CHECK-MESSAGES: :[[@LINE]]:33: warning: the union pointed to by this expression has no field with the type 'const char *'
  const volatile char **U1_V3 = U1; // CHECK-MESSAGES: :[[@LINE]]:33: warning: the union pointed to by this expression has no field with the type 'const volatile char *'
  (volatile char**)       TU1; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'volatile char *'
  (const char**)          TU1; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'const char *'
  (const volatile char**) TU1; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'const volatile char *'
                        U1_V1 = TU1; // CHECK-MESSAGES: :[[@LINE]]:33: warning: the union pointed to by this expression has no field with the type 'volatile char *'
                        U1_V2 = TU1; // CHECK-MESSAGES: :[[@LINE]]:33: warning: the union pointed to by this expression has no field with the type 'const char *'
                        U1_V3 = TU1; // CHECK-MESSAGES: :[[@LINE]]:33: warning: the union pointed to by this expression has no field with the type 'const volatile char *'

  typedef union { const char *Ptr; } TypedefU2;
  TypedefU2 *TU2;
  union { const char *Ptr; } *U2;
  (char**)                U2; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'char *'
  (volatile char**)       U2; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'volatile char *'
  (const volatile char**) U2; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'const volatile char *'
  char                **U2_V1 = U2; // CHECK-MESSAGES: :[[@LINE]]:33: warning: the union pointed to by this expression has no field with the type 'char *'
  volatile char       **U2_V2 = U2; // CHECK-MESSAGES: :[[@LINE]]:33: warning: the union pointed to by this expression has no field with the type 'volatile char *'
  const volatile char **U2_V3 = U2; // CHECK-MESSAGES: :[[@LINE]]:33: warning: the union pointed to by this expression has no field with the type 'const volatile char *'
  (char**)                TU2; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'char *'
  (volatile char**)       TU2; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'volatile char *'
  (const volatile char**) TU2; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'const volatile char *'
                        U2_V1 = TU2; // CHECK-MESSAGES: :[[@LINE]]:33: warning: the union pointed to by this expression has no field with the type 'char *'
                        U2_V2 = TU2; // CHECK-MESSAGES: :[[@LINE]]:33: warning: the union pointed to by this expression has no field with the type 'volatile char *'
                        U2_V3 = TU2; // CHECK-MESSAGES: :[[@LINE]]:33: warning: the union pointed to by this expression has no field with the type 'const volatile char *'

  typedef union { volatile char *Ptr; } TypedefU3;
  TypedefU3 *TU3;
  union { volatile char *Ptr; } *U3;
  (char**)                U3; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'char *'
  (const char**)          U3; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'const char *'
  (const volatile char**) U3; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'const volatile char *'
  char                **U3_V1 = U3; // CHECK-MESSAGES: :[[@LINE]]:33: warning: the union pointed to by this expression has no field with the type 'char *'
  const char          **U3_V2 = U3; // CHECK-MESSAGES: :[[@LINE]]:33: warning: the union pointed to by this expression has no field with the type 'const char *'
  const volatile char **U3_V3 = U3; // CHECK-MESSAGES: :[[@LINE]]:33: warning: the union pointed to by this expression has no field with the type 'const volatile char *'
  (char**)                TU3; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'char *'
  (const char**)          TU3; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'const char *'
  (const volatile char**) TU3; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'const volatile char *'
                        U3_V1 = TU3; // CHECK-MESSAGES: :[[@LINE]]:33: warning: the union pointed to by this expression has no field with the type 'char *'
                        U3_V2 = TU3; // CHECK-MESSAGES: :[[@LINE]]:33: warning: the union pointed to by this expression has no field with the type 'const char *'
                        U3_V3 = TU3; // CHECK-MESSAGES: :[[@LINE]]:33: warning: the union pointed to by this expression has no field with the type 'const volatile char *'

  typedef union { const volatile char *PTR } TypedefU4;
  TypedefU4 *TU4;
  union { const volatile char *Ptr; } *U4;
  (char**)                U4; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'char *'
  (volatile char**)       U4; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'volatile char *'
  (const char**)          U4; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'const char *'
  char                **U4_V1 = U4; // CHECK-MESSAGES: :[[@LINE]]:33: warning: the union pointed to by this expression has no field with the type 'char *'
  volatile char       **U4_V2 = U4; // CHECK-MESSAGES: :[[@LINE]]:33: warning: the union pointed to by this expression has no field with the type 'volatile char *'
  const char          **U4_V3 = U4; // CHECK-MESSAGES: :[[@LINE]]:33: warning: the union pointed to by this expression has no field with the type 'const char *'
  (char**)                TU4; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'char *'
  (volatile char**)       TU4; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'volatile char *'
  (const char**)          TU4; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'const char *'
                        U4_V1 = TU4; // CHECK-MESSAGES: :[[@LINE]]:33: warning: the union pointed to by this expression has no field with the type 'char *'
                        U4_V2 = TU4; // CHECK-MESSAGES: :[[@LINE]]:33: warning: the union pointed to by this expression has no field with the type 'volatile char *'
                        U4_V3 = TU4; // CHECK-MESSAGES: :[[@LINE]]:33: warning: the union pointed to by this expression has no field with the type 'const char *'
}

void castsToTypeWithNoCorresspondingFieldInUnion(union MyUnion *U, TypedefMyUnion *TU) {
  char **V1;
  V1 = U;  // CHECK-MESSAGES: :[[@LINE]]:8: warning: the union pointed to by this expression has no field with the type 'char *'
  V1 = TU; // CHECK-MESSAGES: :[[@LINE]]:8: warning: the union pointed to by this expression has no field with the type 'char *'

  int *V2;
  V2 = U;  // CHECK-MESSAGES: :[[@LINE]]:8: warning: the union pointed to by this expression has no field with the type 'int'
  V2 = TU; // CHECK-MESSAGES: :[[@LINE]]:8: warning: the union pointed to by this expression has no field with the type 'int'

  long *V3;
  V3 = U;  // CHECK-MESSAGES: :[[@LINE]]:8: warning: the union pointed to by this expression has no field with the type 'long'
  V3 = TU; // CHECK-MESSAGES: :[[@LINE]]:8: warning: the union pointed to by this expression has no field with the type 'long'

  double *V4;
  V4 = U;  // CHECK-MESSAGES: :[[@LINE]]:8: warning: the union pointed to by this expression has no field with the type 'double'
  V4 = TU; // CHECK-MESSAGES: :[[@LINE]]:8: warning: the union pointed to by this expression has no field with the type 'double'

  LongPtrTypedef V5;
  V5 = U;  // CHECK-MESSAGES: :[[@LINE]]:8: warning: the union pointed to by this expression has no field with the type 'long'
  V5 = TU; // CHECK-MESSAGES: :[[@LINE]]:8: warning: the union pointed to by this expression has no field with the type 'long'
 
  FloatPtrTypedefPtrTypedef V6;
  V6 = U;  // CHECK-MESSAGES: :[[@LINE]]:8: warning: the union pointed to by this expression has no field with the type 'FloatPtrTypedef'
  V6 = TU; // CHECK-MESSAGES: :[[@LINE]]:8: warning: the union pointed to by this expression has no field with the type 'FloatPtrTypedef'

  (char**)  U; // CHECK-MESSAGES: :[[@LINE]]:13: warning: the union pointed to by this expression has no field with the type 'char *'
  (int*)    U; // CHECK-MESSAGES: :[[@LINE]]:13: warning: the union pointed to by this expression has no field with the type 'int'
  (long*)   U; // CHECK-MESSAGES: :[[@LINE]]:13: warning: the union pointed to by this expression has no field with the type 'long'
  (double*) U; // CHECK-MESSAGES: :[[@LINE]]:13: warning: the union pointed to by this expression has no field with the type 'double'
  (LongPtrTypedef) U; // CHECK-MESSAGES: :[[@LINE]]:20: warning: the union pointed to by this expression has no field with the type 'long'
  (FloatPtrTypedefPtrTypedef) U; // CHECK-MESSAGES: :[[@LINE]]:31: warning: the union pointed to by this expression has no field with the type 'FloatPtrTypedef'

  (char**)  TU; // CHECK-MESSAGES: :[[@LINE]]:13: warning: the union pointed to by this expression has no field with the type 'char *'
  (int*)    TU; // CHECK-MESSAGES: :[[@LINE]]:13: warning: the union pointed to by this expression has no field with the type 'int'
  (long*)   TU; // CHECK-MESSAGES: :[[@LINE]]:13: warning: the union pointed to by this expression has no field with the type 'long'
  (double*) TU; // CHECK-MESSAGES: :[[@LINE]]:13: warning: the union pointed to by this expression has no field with the type 'double'
  (LongPtrTypedef) TU; // CHECK-MESSAGES: :[[@LINE]]:20: warning: the union pointed to by this expression has no field with the type 'long'
  (FloatPtrTypedefPtrTypedef) TU; // CHECK-MESSAGES: :[[@LINE]]:31: warning: the union pointed to by this expression has no field with the type 'FloatPtrTypedef'
}

typedef union Unknown TypedefUnknown;

void castWithUnknownUnionDefinition(union Unknown *U, TypedefUnknown *TU) {
  short  *V1 = U; // CHECK-MESSAGES: :[[@LINE]]:16: warning: the union pointed to by this expression has no field with the type 'short'
  int    *V2 = U; // CHECK-MESSAGES: :[[@LINE]]:16: warning: the union pointed to by this expression has no field with the type 'int'
  long   *V3 = U; // CHECK-MESSAGES: :[[@LINE]]:16: warning: the union pointed to by this expression has no field with the type 'long'
  float  *V4 = U; // CHECK-MESSAGES: :[[@LINE]]:16: warning: the union pointed to by this expression has no field with the type 'float'
  double *V5 = U; // CHECK-MESSAGES: :[[@LINE]]:16: warning: the union pointed to by this expression has no field with the type 'double'
          V1 = TU; // CHECK-MESSAGES: :[[@LINE]]:16: warning: the union pointed to by this expression has no field with the type 'short'
          V2 = TU; // CHECK-MESSAGES: :[[@LINE]]:16: warning: the union pointed to by this expression has no field with the type 'int'
          V3 = TU; // CHECK-MESSAGES: :[[@LINE]]:16: warning: the union pointed to by this expression has no field with the type 'long'
          V4 = TU; // CHECK-MESSAGES: :[[@LINE]]:16: warning: the union pointed to by this expression has no field with the type 'float'
          V5 = TU; // CHECK-MESSAGES: :[[@LINE]]:16: warning: the union pointed to by this expression has no field with the type 'double'

  (short*)  U; // CHECK-MESSAGES: :[[@LINE]]:13: warning: the union pointed to by this expression has no field with the type 'short'
  (int*)    U; // CHECK-MESSAGES: :[[@LINE]]:13: warning: the union pointed to by this expression has no field with the type 'int'
  (long*)   U; // CHECK-MESSAGES: :[[@LINE]]:13: warning: the union pointed to by this expression has no field with the type 'long'
  (float*)  U; // CHECK-MESSAGES: :[[@LINE]]:13: warning: the union pointed to by this expression has no field with the type 'float'
  (double*) U; // CHECK-MESSAGES: :[[@LINE]]:13: warning: the union pointed to by this expression has no field with the type 'double'
  (short*)  TU; // CHECK-MESSAGES: :[[@LINE]]:13: warning: the union pointed to by this expression has no field with the type 'short'
  (int*)    TU; // CHECK-MESSAGES: :[[@LINE]]:13: warning: the union pointed to by this expression has no field with the type 'int'
  (long*)   TU; // CHECK-MESSAGES: :[[@LINE]]:13: warning: the union pointed to by this expression has no field with the type 'long'
  (float*)  TU; // CHECK-MESSAGES: :[[@LINE]]:13: warning: the union pointed to by this expression has no field with the type 'float'
  (double*) TU; // CHECK-MESSAGES: :[[@LINE]]:13: warning: the union pointed to by this expression has no field with the type 'double'
}
