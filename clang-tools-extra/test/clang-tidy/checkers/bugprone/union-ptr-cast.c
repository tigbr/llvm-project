// RUN: %check_clang_tidy %s bugprone-union-ptr-cast %t -- -- \
// RUN: -isystem %S/Inputs/union-ptr-cast/system

typedef short *ShortPtrTypedef;

union MyUnion {
  volatile char *F1;
  const char *F2;
  const volatile char *F3;
  short F4;
  float F5;
  ShortPtrTypedef F6;
};

typedef union MyUnion TypedefMyUnion;

void castToTypeInUnion(union MyUnion *U, TypedefMyUnion *TU) {
  volatile char *V1;
  const char *V2;
  const volatile char *V3;
  short *V4;
  float *V5;
  ShortPtrTypedef *V6;
  V1 = U;
  V2 = U;
  V3 = U;
  V4 = U;
  V5 = U;
  V6 = U;
  V1 = TU;
  V2 = TU;
  V3 = TU;
  V4 = TU;
  V5 = TU;
  V6 = TU;

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
}

void optionDependentDefaultBehaviors(union MyUnion *U, TypedefMyUnion *TU) {
  char *C = U;
  C = TU;
  void *V = U;
  V = TU;
  (char*) U;
  (void*) U;
  (char*) TU;
  (void*) TU;
}

// By default, do not analyze cast expressions where the pointee union
// comes from from a system header file. C has no namespaces, so that
// is omitted from this file.

#include <pthread.h>

void fromSystemHeaderFile(pthread_mutex_t *T) {
  void *P = T;
  (void*) T;
}

void irrelevantCastExpressions(union MyUnion *U, TypedefMyUnion *TU) {
  long LI;
  unsigned long UL = LI;
  (unsigned long) LI;
  (void*) LI;

  // It does not matter that the union has a field with the same type
  // as the aliased type. Typedefs and usings are not considered "transparent"
  // in that sense by the check.
  ShortPtrTypedef V5 = U;
  (ShortPtrTypedef) U;

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

void castsToTypesWithNoCorresspondingFieldInUnion(union MyUnion *U, TypedefMyUnion *TU) {
  char  **V1 = U; // CHECK-MESSAGES: :[[@LINE]]:16: warning: the union pointed to by this expression has no field with the type 'char *'
  int    *V2 = U; // CHECK-MESSAGES: :[[@LINE]]:16: warning: the union pointed to by this expression has no field with the type 'int'
  long   *V3 = U; // CHECK-MESSAGES: :[[@LINE]]:16: warning: the union pointed to by this expression has no field with the type 'long'
  double *V4 = U; // CHECK-MESSAGES: :[[@LINE]]:16: warning: the union pointed to by this expression has no field with the type 'double'
          V1 = TU; // CHECK-MESSAGES: :[[@LINE]]:16: warning: the union pointed to by this expression has no field with the type 'char *'
          V2 = TU; // CHECK-MESSAGES: :[[@LINE]]:16: warning: the union pointed to by this expression has no field with the type 'int'
          V3 = TU; // CHECK-MESSAGES: :[[@LINE]]:16: warning: the union pointed to by this expression has no field with the type 'long'
          V4 = TU; // CHECK-MESSAGES: :[[@LINE]]:16: warning: the union pointed to by this expression has no field with the type 'double'

  (int*)    U; // CHECK-MESSAGES: :[[@LINE]]:13: warning: the union pointed to by this expression has no field with the type 'int'
  (long*)   U; // CHECK-MESSAGES: :[[@LINE]]:13: warning: the union pointed to by this expression has no field with the type 'long'
  (double*) U; // CHECK-MESSAGES: :[[@LINE]]:13: warning: the union pointed to by this expression has no field with the type 'double'
  (int*)    TU; // CHECK-MESSAGES: :[[@LINE]]:13: warning: the union pointed to by this expression has no field with the type 'int'
  (long*)   TU; // CHECK-MESSAGES: :[[@LINE]]:13: warning: the union pointed to by this expression has no field with the type 'long'
  (double*) TU; // CHECK-MESSAGES: :[[@LINE]]:13: warning: the union pointed to by this expression has no field with the type 'double'
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
