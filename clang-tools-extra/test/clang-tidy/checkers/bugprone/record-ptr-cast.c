// RUN: %check_clang_tidy %s bugprone-record-ptr-cast %t -- -- \
// RUN: -isystem %S/Inputs/record-ptr-cast/system

#include <pthread.h>

void tests() {

  /*
   * casting a record pointer to itself is accepted
   * for unions any field is suitable,
   * for structs and classes only first field is suitable,
   * extra qualifiers are accepted
   * completely missing types are not accepted
   * casting to a pointer behind alias is handled
   *
   */
  {
  typedef long *LongPtrTypedef;

  union Union { int i; float f; };
  typedef union Union TypedefUnion;

  union Union  *U1;
  TypedefUnion *U2;

  struct Struct { int i; float f; };
  typedef struct Struct TypedefStruct;

  struct Struct *S1;
  TypedefStruct *S2;

  union Union *U_ = U1;
  (union Union*) U1;

  TypedefUnion *TU_ = U2;
  (TypedefUnion*) U2;


  struct Struct *S_ = S1;
  (struct Struct*) S1;

  TypedefStruct *TS_ = S2;
  (TypedefStruct*) S2;

  (int*) U1;
  (int*) U2;

  (int*) S1;
  (int*) S2;

  (const int*) U1;
  (const int*) U2;

  (const int*) S1;
  (const int*) S2;

  (volatile int*) U1;
  (volatile int*) U2;

  (volatile int*) S1;
  (volatile int*) S2;

  (const volatile int*) U1;
  (const volatile int*) U2;

  (const volatile int*) S1;
  (const volatile int*) S2;

  (float*) U1;
  (float*) U2;

  (float*) S1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'struct Struct *' to 'float *'
  (float*) S2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefStruct *' to 'float *'

  (long*) U1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Union *' to 'long *'
  (long*) U2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnion *' to 'long *'

  (LongPtrTypedef) U1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Union *' to 'long *'
  (LongPtrTypedef) U2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnion *' to 'long *'
  }

  /* fewer qualifiers are not accepted */
  {
  union Union { const volatile int i; };
  typedef union Union TypedefUnion;

  union Union  *U1;
  TypedefUnion *U2;

  struct Struct { const volatile int i; };
  typedef struct Struct TypedefStruct;

  struct Struct *S1;
  TypedefStruct *S2;

  (int*) U1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Union *' to 'int *'
  (int*) U2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnion *' to 'int *'

  (int*) S1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'struct Struct *' to 'int *'
  (int*) S2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefStruct *' to 'int *'

  (const int*) U1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Union *' to 'const int *'
  (const int*) U2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnion *' to 'const int *'
                                                                                                               
  (const int*) S1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'struct Struct *' to 'const int *'
  (const int*) S2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefStruct *' to 'const int *'

  (volatile int*) U1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Union *' to 'volatile int *'
  (volatile int*) U2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnion *' to 'volatile int *'
                                                                                                                  
  (volatile int*) S1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'struct Struct *' to 'volatile int *'
  (volatile int*) S2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefStruct *' to 'volatile int *'

  (const volatile int*) U1;
  (const volatile int*) U2;

  (const volatile int*) S1;
  (const volatile int*) S2;
  }

  /*
   * default option behavior of AlwaysAllowCastToCharPtr
   */
  {
  union Union { const volatile int i; };
  typedef union Union TypedefUnion;

  union Union  *U1;
  TypedefUnion *U2;

  struct Struct { const volatile int i; };
  typedef struct Struct TypedefStruct;

  struct Struct *S1;
  TypedefStruct *S2;

  (char*) U1;
  (char*) U2;
  (char*) S1;
  (char*) S2;

  (const char*) U1;
  (const char*) U2;
  (const char*) S1;
  (const char*) S2;

  (volatile char*) U1;
  (volatile char*) U2;
  (volatile char*) S1;
  (volatile char*) S2;

  (const volatile char*) U1;
  (const volatile char*) U2;
  (const volatile char*) S1;
  (const volatile char*) S2;

  void *V;
  V = U1;
  V = U2;
  V = S1;
  V = S2;

  const void *CV;
  CV = U1;
  CV = U2;
  CV = S1;
  CV = S2;

  volatile void *VV;
  VV = U1;
  VV = U2;
  VV = S1;
  VV = S2;

  const volatile void *CVV;
  CVV = U1;
  CVV = U2;
  CVV = S1;
  CVV = S2;

  (void*) U1;
  (void*) U2;
  (void*) S1;
  (void*) S2;

  (const void*) U1;
  (const void*) U2;
  (const void*) S1;
  (const void*) S2;

  (volatile void*) U1;
  (volatile void*) U2;
  (volatile void*) S1;
  (volatile void*) S2;

  (const volatile void*) U1;
  (const volatile void*) U2;
  (const volatile void*) S1;
  (const volatile void*) S2;
  }

  /* Default behavior of option IgnoreIfRecordIsFromSystemHeader */
  {
    pthread_mutex_t *T2;
    double *dptr = T2;
    (double*) T2;
  }

  /* CompareCanonicalTypes option default behavior */
  {
  typedef int TypedefInt;
  typedef short *ShortPtrTypedef;
  typedef ShortPtrTypedef ShortPtrTypedefTypedef;
  typedef ShortPtrTypedef *ShortPtrTypedefPtr;
  typedef long *LongPtrTypedef;

  union Union {
    TypedefInt i;
    short S;
    ShortPtrTypedef SPT;
  };
  typedef union Union TypedefUnion;

  union Union  *U1;
  TypedefUnion *U2;

  struct Struct { union Union U; };
  typedef struct Struct TypedefStruct;

  struct Struct *S1;
  TypedefStruct *S2;

  (int*) U1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Union *' to 'int *'
  (int*) U2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnion *' to 'int *'

  (int*) S1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'struct Struct *' to 'int *'
  (int*) S2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefStruct *' to 'int *'

  (ShortPtrTypedef) U1;
  (ShortPtrTypedef*) U1;
  (ShortPtrTypedefPtr) U1;
  (ShortPtrTypedefTypedef) U1;

  (ShortPtrTypedef) U2;
  (ShortPtrTypedef*) U2;
  (ShortPtrTypedefPtr) U2;
  (ShortPtrTypedefTypedef) U2;

  (ShortPtrTypedef) S1;
  (ShortPtrTypedef*) S1;
  (ShortPtrTypedefPtr) S1;
  (ShortPtrTypedefTypedef) S1;

  (ShortPtrTypedef) S2;
  (ShortPtrTypedef*) S2;
  (ShortPtrTypedefPtr) S2;
  (ShortPtrTypedefTypedef) S2;
  }

  /* Cast to subobject type tests */
  {
  struct Bar {
    float F;
  };
  
  struct Foo {
    struct Bar B;
    int I;
  };

  union Union { struct Foo F; };
  typedef union Union TypedefUnion;

  union Union  *U1;
  TypedefUnion *U2;

  struct Struct { struct Foo F; };
  typedef struct Struct TypedefStruct;

  struct Struct *S1;
  TypedefStruct *S2;

  (struct Foo*) U1;
  (struct Foo*) U2;
  (struct Foo*) S1;
  (struct Foo*) S2;

  (float*) U1;
  (float*) U2;

  (float*) S1;
  (float*) S2;

  (int*) U1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Union *' to 'int *'
  (int*) U2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnion *' to 'int *'

  (int*) S1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'struct Struct *' to 'int *'
  (int*) S2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefStruct *' to 'int *'
  }

  /*
   * Casting pointer to record which has no definition is disallowed, except to
   * char* and void*.
   */
  {
  union Union;
  typedef union Union TypedefUnion;

  union Union  *U1;
  TypedefUnion *U2;

  struct Struct;
  typedef struct Struct TypedefStruct;

  struct Struct *S1;
  TypedefStruct *S2;

  (char*) U1;
  (char*) U2;

  (char*) S1;
  (char*) S2;

  (void*) U1;
  (void*) U2;

  (void*) S1;
  (void*) S2;

  (int*) U1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Union *' to 'int *'
  (int*) U2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnion *' to 'int *'

  (int*) S1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'struct Struct *' to 'int *'
  (int*) S2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefStruct *' to 'int *'
  }
}
