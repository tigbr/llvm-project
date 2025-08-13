// RUN: %check_clang_tidy %s bugprone-union-ptr-cast %t

typedef short *short_ptr_typedef;

union MyUnion {
  volatile char *vptr;
  const char *cptr;
  const volatile char *vcptr;
  short s;
  float f;
  short_ptr_typedef spt;
};

void castToTypeInUnion(union MyUnion *U) {
  volatile char *V1 = U;
  const char *V2 = U;
  const volatile char *V3 = U;
  short *V4 = U;
  float *V5 = U;
  short_ptr_typedef *V6 = U;

  (volatile char**) U;
  (const char**) U;
  (const volatile char**) U;
  (short*) U;
  (float*) U;
  (short_ptr_typedef*) U;
}

void option_dependent_default_behaviors(union MyUnion *U) {
  char *c = U;
  void *v = U;
  (char*) U;
  (void*) U;
}

void castsWithQualifierMismatches() {
  union { char *Ptr; }   *U1;
  (volatile char**)       U1; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'volatile char *'
  (const char**)          U1; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'const char *'
  (const volatile char**) U1; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'const volatile char *'
  volatile char       **U1_V1 = U1; // CHECK-MESSAGES: :[[@LINE]]:33: warning: the union pointed to by this expression has no field with the type 'volatile char *'
  const char          **U1_V2 = U1; // CHECK-MESSAGES: :[[@LINE]]:33: warning: the union pointed to by this expression has no field with the type 'const char *'
  const volatile char **U1_V3 = U1; // CHECK-MESSAGES: :[[@LINE]]:33: warning: the union pointed to by this expression has no field with the type 'const volatile char *'

  union { const char *Ptr; } *U2;
  (char**)                U2; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'char *'
  (volatile char**)       U2; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'volatile char *'
  (const volatile char**) U2; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'const volatile char *'
  char                **U2_V1 = U2; // CHECK-MESSAGES: :[[@LINE]]:33: warning: the union pointed to by this expression has no field with the type 'char *'
  volatile char       **U2_V2 = U2; // CHECK-MESSAGES: :[[@LINE]]:33: warning: the union pointed to by this expression has no field with the type 'volatile char *'
  const volatile char **U2_V3 = U2; // CHECK-MESSAGES: :[[@LINE]]:33: warning: the union pointed to by this expression has no field with the type 'const volatile char *'

  union { volatile char *Ptr; } *U3;
  (char**)                U3; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'char *'
  (const char**)          U3; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'const char *'
  (const volatile char**) U3; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'const volatile char *'
  char                **U3_V1 = U3; // CHECK-MESSAGES: :[[@LINE]]:33: warning: the union pointed to by this expression has no field with the type 'char *'
  const char          **U3_V2 = U3; // CHECK-MESSAGES: :[[@LINE]]:33: warning: the union pointed to by this expression has no field with the type 'const char *'
  const volatile char **U3_V3 = U3; // CHECK-MESSAGES: :[[@LINE]]:33: warning: the union pointed to by this expression has no field with the type 'const volatile char *'

  union { const volatile char *Ptr; } *U4;
  (char**)                U4; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'char *'
  (volatile char**)       U4; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'volatile char *'
  (const char**)          U4; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'const char *'
  char                **U4_V1 = U4; // CHECK-MESSAGES: :[[@LINE]]:33: warning: the union pointed to by this expression has no field with the type 'char *'
  volatile char       **U4_V2 = U4; // CHECK-MESSAGES: :[[@LINE]]:33: warning: the union pointed to by this expression has no field with the type 'volatile char *'
  const char          **U4_V3 = U4; // CHECK-MESSAGES: :[[@LINE]]:33: warning: the union pointed to by this expression has no field with the type 'const char *'
}

void castsToTypesWithNoCorresspondingFieldInUnion(union MyUnion *U) {
  char  **V1 = U; // CHECK-MESSAGES: :[[@LINE]]:16: warning: the union pointed to by this expression has no field with the type 'char *'
  int    *V2 = U; // CHECK-MESSAGES: :[[@LINE]]:16: warning: the union pointed to by this expression has no field with the type 'int'
  long   *V3 = U; // CHECK-MESSAGES: :[[@LINE]]:16: warning: the union pointed to by this expression has no field with the type 'long'
  double *V4 = U; // CHECK-MESSAGES: :[[@LINE]]:16: warning: the union pointed to by this expression has no field with the type 'double'

  (int*)    U; // CHECK-MESSAGES: :[[@LINE]]:13: warning: the union pointed to by this expression has no field with the type 'int'
  (long*)   U; // CHECK-MESSAGES: :[[@LINE]]:13: warning: the union pointed to by this expression has no field with the type 'long'
  (double*) U; // CHECK-MESSAGES: :[[@LINE]]:13: warning: the union pointed to by this expression has no field with the type 'double'
}

void castWithUnknownUnionDefinition(union Unknown *U) {
  short  *V1 = U; // CHECK-MESSAGES: :[[@LINE]]:16: warning: the union pointed to by this expression has no field with the type 'short'
  int    *V2 = U; // CHECK-MESSAGES: :[[@LINE]]:16: warning: the union pointed to by this expression has no field with the type 'int'
  long   *V3 = U; // CHECK-MESSAGES: :[[@LINE]]:16: warning: the union pointed to by this expression has no field with the type 'long'
  float  *V4 = U; // CHECK-MESSAGES: :[[@LINE]]:16: warning: the union pointed to by this expression has no field with the type 'float'
  double *V5 = U; // CHECK-MESSAGES: :[[@LINE]]:16: warning: the union pointed to by this expression has no field with the type 'double'

  (short*)  U; // CHECK-MESSAGES: :[[@LINE]]:13: warning: the union pointed to by this expression has no field with the type 'short'
  (int*)    U; // CHECK-MESSAGES: :[[@LINE]]:13: warning: the union pointed to by this expression has no field with the type 'int'
  (long*)   U; // CHECK-MESSAGES: :[[@LINE]]:13: warning: the union pointed to by this expression has no field with the type 'long'
  (float*)  U; // CHECK-MESSAGES: :[[@LINE]]:13: warning: the union pointed to by this expression has no field with the type 'float'
  (double*) U; // CHECK-MESSAGES: :[[@LINE]]:13: warning: the union pointed to by this expression has no field with the type 'double'
}

void irrelevantCastExpressions(union MyUnion *U, long i) {
  long LI;
  unsigned long UL = LI;
  (unsigned long) LI;
  (void*) LI;

  // It does not matter that the union has a field with the same type
  // as the aliased type. Typedefs and usings are not considered "transparent"
  // in that sense.
  short_ptr_typedef V5 = U;
  (short_ptr_typedef) U;
}
