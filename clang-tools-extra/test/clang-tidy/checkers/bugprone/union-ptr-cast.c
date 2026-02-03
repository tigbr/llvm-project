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
  volatile int *F1;
  const int *F2;
  const volatile int *F3;
  short F4;
  float F5;
  ShortPtrTypedef F6;
  union FooBar F7;
};

typedef union MyUnion TypedefMyUnion;

void castToTypeInUnion(union MyUnion *U, TypedefMyUnion *TU) {
  volatile int **V1;
  V1 = U;
  V1 = TU;

  const int **V2;
  V2 = U;
  V2 = TU;

  const volatile int **V3;
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

  (volatile int**) U;
  (volatile int**) TU;
  (const int**) U;
  (const int**) TU;
  (const volatile int**) U;
  (const volatile int**) TU;
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
  /* AllowCastToBaseClass */
  // No test cases here, there is no inheritance in C.

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
  SubFieldPtr4 = U;  // CHECK-MESSAGES: :[[@LINE]]:18: warning: invalid cast from 'union MyUnion *' to 'void ***'
  SubFieldPtr4 = TU; // CHECK-MESSAGES: :[[@LINE]]:18: warning: invalid cast from 'TypedefMyUnion *' to 'void ***'
  (void ***) U;      // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union MyUnion *' to 'void ***'
  (void ***) TU;     // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefMyUnion *' to 'void ***'

  void **SubFieldPtr5;
  SubFieldPtr5 = U;
  SubFieldPtr5 = TU;
  (void **) U;
  (void **) TU;

  /* AlwaysAllowCastToCharPtr */
  char *C;
  C = U;
  C = TU;
  const char *CC;
  CC = U;
  CC = TU;
  volatile char *VC;
  VC = U;
  VC = TU;
  const volatile char *CVC;
  CVC = U;
  CVC = TU;
  (char*) U;
  (char*) TU;
  (const char*) U;
  (const char*) TU;
  (volatile char*) U;
  (volatile char*) TU;
  (const volatile char*) U;
  (const volatile char*) TU;

  /* AlwaysAllowCastToVoidPtr */
  void *V;
  V = U;
  V = TU;
  const void *CV;
  CV = U;
  CV = TU;
  volatile void *VV;
  VV = U;
  VV = TU;
  const volatile void *CVV;
  CVV = U;
  CVV = TU;
  (void*) U;
  (void*) TU;
  (const void*) U;
  (const void*) TU;
  (volatile void*) U;
  (volatile void*) TU;
  (const volatile void*) U;
  (const volatile void*) TU;

  /* CompareCanonicalTypes */
  (ShortPtrTypedef) U;
  (ShortPtrTypedef*) U;
  (ShortPtrTypedefPtr) U;
  (ShortPtrTypedefTypedef) U;

  (ShortPtrTypedef) TU;
  (ShortPtrTypedef*) TU;
  (ShortPtrTypedefPtr) TU;
  (ShortPtrTypedefTypedef) TU;

  /* IgnoreIfUnionIsFromStdNamespace */
  // No test cases here, C has no namespaces.

  /* IgnoreIfUnionIsFromSystemHeader */
  // By default, do not analyze cast expressions where the pointee union
  // comes from from a system header file. C has no namespaces, so that
  // is omitted from this file.
  pthread_mutex_t *T;
  void *P = T;
  (void*) T;
}

void doNotWarnAboutThese(union MyUnion *U, TypedefMyUnion *TU) {
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
  union QTUnion1 { char *Ptr; }   *U1;
  (volatile char**)       U1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union QTUnion1 *' to 'volatile char **'
  (const char**)          U1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union QTUnion1 *' to 'const char **'
  (const volatile char**) U1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union QTUnion1 *' to 'const volatile char **'
  volatile char       **U1_V1 = U1; // CHECK-MESSAGES: :[[@LINE]]:33: warning: invalid cast from 'union QTUnion1 *' to 'volatile char **'
  const char          **U1_V2 = U1; // CHECK-MESSAGES: :[[@LINE]]:33: warning: invalid cast from 'union QTUnion1 *' to 'const char **'
  const volatile char **U1_V3 = U1; // CHECK-MESSAGES: :[[@LINE]]:33: warning: invalid cast from 'union QTUnion1 *' to 'const volatile char **'
  (volatile char**)       TU1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefU1 *' to 'volatile char **'
  (const char**)          TU1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefU1 *' to 'const char **'
  (const volatile char**) TU1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefU1 *' to 'const volatile char **'
                        U1_V1 = TU1; // CHECK-MESSAGES: :[[@LINE]]:33: warning: invalid cast from 'TypedefU1 *' to 'volatile char **'
                        U1_V2 = TU1; // CHECK-MESSAGES: :[[@LINE]]:33: warning: invalid cast from 'TypedefU1 *' to 'const char **'
                        U1_V3 = TU1; // CHECK-MESSAGES: :[[@LINE]]:33: warning: invalid cast from 'TypedefU1 *' to 'const volatile char **'

  typedef union { const char *Ptr; } TypedefU2;
  TypedefU2 *TU2;
  union QTUnion2 { const char *Ptr; } *U2;
  (char**)                U2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union QTUnion2 *' to 'char **'
  (volatile char**)       U2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union QTUnion2 *' to 'volatile char **'
  (const volatile char**) U2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union QTUnion2 *' to 'const volatile char **'
  char                **U2_V1 = U2; // CHECK-MESSAGES: :[[@LINE]]:33: warning: invalid cast from 'union QTUnion2 *' to 'char **'
  volatile char       **U2_V2 = U2; // CHECK-MESSAGES: :[[@LINE]]:33: warning: invalid cast from 'union QTUnion2 *' to 'volatile char **'
  const volatile char **U2_V3 = U2; // CHECK-MESSAGES: :[[@LINE]]:33: warning: invalid cast from 'union QTUnion2 *' to 'const volatile char **'
  (char**)                TU2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefU2 *' to 'char **'
  (volatile char**)       TU2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefU2 *' to 'volatile char **'
  (const volatile char**) TU2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefU2 *' to 'const volatile char **'
                        U2_V1 = TU2; // CHECK-MESSAGES: :[[@LINE]]:33: warning: invalid cast from 'TypedefU2 *' to 'char **'
                        U2_V2 = TU2; // CHECK-MESSAGES: :[[@LINE]]:33: warning: invalid cast from 'TypedefU2 *' to 'volatile char **'
                        U2_V3 = TU2; // CHECK-MESSAGES: :[[@LINE]]:33: warning: invalid cast from 'TypedefU2 *' to 'const volatile char **'

  typedef union { volatile char *Ptr; } TypedefU3;
  TypedefU3 *TU3;
  union QTUnion3 { volatile char *Ptr; } *U3;
  (char**)                U3; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union QTUnion3 *' to 'char **'
  (const char**)          U3; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union QTUnion3 *' to 'const char **'
  (const volatile char**) U3; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union QTUnion3 *' to 'const volatile char **'
  char                **U3_V1 = U3; // CHECK-MESSAGES: :[[@LINE]]:33: warning: invalid cast from 'union QTUnion3 *' to 'char **'
  const char          **U3_V2 = U3; // CHECK-MESSAGES: :[[@LINE]]:33: warning: invalid cast from 'union QTUnion3 *' to 'const char **'
  const volatile char **U3_V3 = U3; // CHECK-MESSAGES: :[[@LINE]]:33: warning: invalid cast from 'union QTUnion3 *' to 'const volatile char **'
  (char**)                TU3; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefU3 *' to 'char **'
  (const char**)          TU3; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefU3 *' to 'const char **'
  (const volatile char**) TU3; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefU3 *' to 'const volatile char **'
                        U3_V1 = TU3; // CHECK-MESSAGES: :[[@LINE]]:33: warning: invalid cast from 'TypedefU3 *' to 'char **'
                        U3_V2 = TU3; // CHECK-MESSAGES: :[[@LINE]]:33: warning: invalid cast from 'TypedefU3 *' to 'const char **'
                        U3_V3 = TU3; // CHECK-MESSAGES: :[[@LINE]]:33: warning: invalid cast from 'TypedefU3 *' to 'const volatile char **'

  union QTUnion4 { const volatile char *Ptr; } *U4;
  typedef union QTUnion4 TypedefU4;
  TypedefU4 *TU4;
  (char**)                U4; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union QTUnion4 *' to 'char **'
  (volatile char**)       U4; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union QTUnion4 *' to 'volatile char **'
  (const char**)          U4; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union QTUnion4 *' to 'const char **'
  char          **U4_V1 = U4; // CHECK-MESSAGES: :[[@LINE]]:27: warning: invalid cast from 'union QTUnion4 *' to 'char **'
  volatile char **U4_V2 = U4; // CHECK-MESSAGES: :[[@LINE]]:27: warning: invalid cast from 'union QTUnion4 *' to 'volatile char **'
  const char    **U4_V3 = U4; // CHECK-MESSAGES: :[[@LINE]]:27: warning: invalid cast from 'union QTUnion4 *' to 'const char **'
  (char**)                TU4; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefU4 *' to 'char **'
  (volatile char**)       TU4; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefU4 *' to 'volatile char **'
  (const char**)          TU4; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefU4 *' to 'const char **'
                  U4_V1 = TU4; // CHECK-MESSAGES: :[[@LINE]]:27: warning: invalid cast from 'TypedefU4 *' to 'char **'
                  U4_V2 = TU4; // CHECK-MESSAGES: :[[@LINE]]:27: warning: invalid cast from 'TypedefU4 *' to 'volatile char **'
                  U4_V3 = TU4; // CHECK-MESSAGES: :[[@LINE]]:27: warning: invalid cast from 'TypedefU4 *' to 'const char **'
}

void castsToTypeWithNoCorresspondingFieldInUnion(union MyUnion *U, TypedefMyUnion *TU) {
  char **V1;
  V1 = U;  // CHECK-MESSAGES: :[[@LINE]]:8: warning: invalid cast from 'union MyUnion *' to 'char **'
  V1 = TU; // CHECK-MESSAGES: :[[@LINE]]:8: warning: invalid cast from 'TypedefMyUnion *' to 'char **'

  int *V2;
  V2 = U;  // CHECK-MESSAGES: :[[@LINE]]:8: warning: invalid cast from 'union MyUnion *' to 'int *'
  V2 = TU; // CHECK-MESSAGES: :[[@LINE]]:8: warning: invalid cast from 'TypedefMyUnion *' to 'int *'

  long *V3;
  V3 = U;  // CHECK-MESSAGES: :[[@LINE]]:8: warning: invalid cast from 'union MyUnion *' to 'long *'
  V3 = TU; // CHECK-MESSAGES: :[[@LINE]]:8: warning: invalid cast from 'TypedefMyUnion *' to 'long *'

  double *V4;
  V4 = U;  // CHECK-MESSAGES: :[[@LINE]]:8: warning: invalid cast from 'union MyUnion *' to 'double *'
  V4 = TU; // CHECK-MESSAGES: :[[@LINE]]:8: warning: invalid cast from 'TypedefMyUnion *' to 'double *'

  LongPtrTypedef V5;
  V5 = U;  // CHECK-MESSAGES: :[[@LINE]]:8: warning: invalid cast from 'union MyUnion *' to 'long *'
  V5 = TU; // CHECK-MESSAGES: :[[@LINE]]:8: warning: invalid cast from 'TypedefMyUnion *' to 'long *'
 
  FloatPtrTypedefPtrTypedef V6;
  V6 = U;  // CHECK-MESSAGES: :[[@LINE]]:8: warning: invalid cast from 'union MyUnion *' to 'FloatPtrTypedef *'
  V6 = TU; // CHECK-MESSAGES: :[[@LINE]]:8: warning: invalid cast from 'TypedefMyUnion *' to 'FloatPtrTypedef *'

  (char**)  U; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union MyUnion *' to 'char **'
  (int*)    U; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union MyUnion *' to 'int *'
  (long*)   U; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union MyUnion *' to 'long *'
  (double*) U; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union MyUnion *' to 'double *'
  (LongPtrTypedef) U; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union MyUnion *' to 'long *'
  (FloatPtrTypedefPtrTypedef) U; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union MyUnion *' to 'FloatPtrTypedef *'

  (char**)  TU; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefMyUnion *' to 'char **'
  (int*)    TU; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefMyUnion *' to 'int *'
  (long*)   TU; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefMyUnion *' to 'long *'
  (double*) TU; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefMyUnion *' to 'double *'
  (LongPtrTypedef) TU; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefMyUnion *' to 'long *'
  (FloatPtrTypedefPtrTypedef) TU; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefMyUnion *' to 'FloatPtrTypedef *'
}

typedef union Unknown TypedefUnknown;

void castWithUnknownUnionDefinition(union Unknown *U, TypedefUnknown *TU) {
  short  *V1 = U; // CHECK-MESSAGES: :[[@LINE]]:16: warning: invalid cast from 'union Unknown *' to 'short *'
  int    *V2 = U; // CHECK-MESSAGES: :[[@LINE]]:16: warning: invalid cast from 'union Unknown *' to 'int *'
  long   *V3 = U; // CHECK-MESSAGES: :[[@LINE]]:16: warning: invalid cast from 'union Unknown *' to 'long *'
  float  *V4 = U; // CHECK-MESSAGES: :[[@LINE]]:16: warning: invalid cast from 'union Unknown *' to 'float *'
  double *V5 = U; // CHECK-MESSAGES: :[[@LINE]]:16: warning: invalid cast from 'union Unknown *' to 'double *'
          V1 = TU; // CHECK-MESSAGES: :[[@LINE]]:16: warning: invalid cast from 'TypedefUnknown *' to 'short *'
          V2 = TU; // CHECK-MESSAGES: :[[@LINE]]:16: warning: invalid cast from 'TypedefUnknown *' to 'int *'
          V3 = TU; // CHECK-MESSAGES: :[[@LINE]]:16: warning: invalid cast from 'TypedefUnknown *' to 'long *'
          V4 = TU; // CHECK-MESSAGES: :[[@LINE]]:16: warning: invalid cast from 'TypedefUnknown *' to 'float *'
          V5 = TU; // CHECK-MESSAGES: :[[@LINE]]:16: warning: invalid cast from 'TypedefUnknown *' to 'double *'

  (short*)  U; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Unknown *' to 'short *'
  (int*)    U; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Unknown *' to 'int *'
  (long*)   U; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Unknown *' to 'long *'
  (float*)  U; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Unknown *' to 'float *'
  (double*) U; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Unknown *' to 'double *'
  (short*)  TU; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnknown *' to 'short *'
  (int*)    TU; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnknown *' to 'int *'
  (long*)   TU; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnknown *' to 'long *'
  (float*)  TU; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnknown *' to 'float *'
  (double*) TU; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnknown *' to 'double *'
}
