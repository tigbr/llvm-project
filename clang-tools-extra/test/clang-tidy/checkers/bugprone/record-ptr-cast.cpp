// RUN: %check_clang_tidy -std=c++98-or-later %s bugprone-record-ptr-cast %t -- -- \
// RUN: -I%S/Inputs/record-ptr-cast \
// RUN: -isystem %S/Inputs/record-ptr-cast/system

#include "stdnamespace.h"
#include <pthread.h>

void tests() {

  /*
   * casting derived records to their parents is accepted
   */
  {
  class Base { int I; };
  class PublicDerived : public Base { };

  // nullptr is from C++11
  Base *B = 0;
  PublicDerived *D = 0;

  B = B;
  (Base*) B;
  reinterpret_cast<Base*>(B);
  static_cast<Base*>(B);
  dynamic_cast<Base*>(B);

  D = D;
  (PublicDerived*) D;
  reinterpret_cast<PublicDerived*>(D);
  static_cast<PublicDerived*>(D);
  dynamic_cast<PublicDerived*>(D);

  B = D;
  (Base*) D;
  reinterpret_cast<Base*>(D);
  static_cast<Base*>(D);
  dynamic_cast<Base*>(D);
  }

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
  using LongPtrUsing = long*;

  union Union { int i; float f; };
  typedef union Union TypedefUnion;
  using UsingUnion = union Union;

  union Union  *U1;
  TypedefUnion *U2;
  UsingUnion   *U3;

  struct Struct { int i; float f; };
  typedef struct Struct TypedefStruct;
  using UsingStruct = struct Struct;

  struct Struct *S1;
  TypedefStruct *S2;
  UsingStruct   *S3;

  class Class { int i; float f; };
  typedef class Class TypedefClass;
  using UsingClass = class Class;

  class Class  *C1;
  TypedefClass *C2;
  UsingClass   *C3;

  union Union *U_ = U1;
  (union Union*) U1;
  reinterpret_cast<union Union*>(U1);

  TypedefUnion *TU_ = U2;
  (TypedefUnion*) U2;
  reinterpret_cast<TypedefUnion*>(U2);

  UsingUnion *UU_ = U3;
  (UsingUnion*) U3;
  reinterpret_cast<UsingUnion*>(U3);

  struct Struct *S_ = S1;
  (struct Struct*) S1;
  reinterpret_cast<struct Struct*>(S1);

  TypedefStruct *TS_ = S2;
  (TypedefStruct*) S2;
  reinterpret_cast<TypedefStruct*>(S2);

  UsingStruct *US_ = S3;
  (UsingStruct*) S3;
  reinterpret_cast<UsingStruct*>(S3);

  class Class *C_ = C1;
  (class Class*) C1;
  reinterpret_cast<class Class*>(C1);

  TypedefClass *TC_ = C2;
  (TypedefClass*) C2;
  reinterpret_cast<TypedefClass*>(C2);

  UsingClass *UC_ = C3;
  (UsingClass*) C3;
  reinterpret_cast<UsingClass*>(C3);

  (int*) U1;
  (int*) U2;
  (int*) U3;

  (int*) S1;
  (int*) S2;
  (int*) S3;

  (int*) C1;
  (int*) C2;
  (int*) C3;

  reinterpret_cast<int*>(U1);
  reinterpret_cast<int*>(U2);
  reinterpret_cast<int*>(U3);

  reinterpret_cast<int*>(S1);
  reinterpret_cast<int*>(S2);
  reinterpret_cast<int*>(S3);

  reinterpret_cast<int*>(C1);
  reinterpret_cast<int*>(C2);
  reinterpret_cast<int*>(C3);

  (const int*) U1;
  (const int*) U2;
  (const int*) U3;

  (const int*) S1;
  (const int*) S2;
  (const int*) S3;

  (const int*) C1;
  (const int*) C2;
  (const int*) C3;

  reinterpret_cast<const int*>(U1);
  reinterpret_cast<const int*>(U2);
  reinterpret_cast<const int*>(U3);

  reinterpret_cast<const int*>(S1);
  reinterpret_cast<const int*>(S2);
  reinterpret_cast<const int*>(S3);

  reinterpret_cast<const int*>(C1);
  reinterpret_cast<const int*>(C2);
  reinterpret_cast<const int*>(C3);

  (volatile int*) U1;
  (volatile int*) U2;
  (volatile int*) U3;

  (volatile int*) S1;
  (volatile int*) S2;
  (volatile int*) S3;

  (volatile int*) C1;
  (volatile int*) C2;
  (volatile int*) C3;

  reinterpret_cast<volatile int*>(U1);
  reinterpret_cast<volatile int*>(U2);
  reinterpret_cast<volatile int*>(U3);

  reinterpret_cast<volatile int*>(S1);
  reinterpret_cast<volatile int*>(S2);
  reinterpret_cast<volatile int*>(S3);

  reinterpret_cast<volatile int*>(C1);
  reinterpret_cast<volatile int*>(C2);
  reinterpret_cast<volatile int*>(C3);

  (const volatile int*) U1;
  (const volatile int*) U2;
  (const volatile int*) U3;

  (const volatile int*) S1;
  (const volatile int*) S2;
  (const volatile int*) S3;

  (const volatile int*) C1;
  (const volatile int*) C2;
  (const volatile int*) C3;

  reinterpret_cast<const volatile int*>(U1);
  reinterpret_cast<const volatile int*>(U2);
  reinterpret_cast<const volatile int*>(U3);

  reinterpret_cast<const volatile int*>(S1);
  reinterpret_cast<const volatile int*>(S2);
  reinterpret_cast<const volatile int*>(S3);

  reinterpret_cast<const volatile int*>(C1);
  reinterpret_cast<const volatile int*>(C2);
  reinterpret_cast<const volatile int*>(C3);

  (float*) U1;
  (float*) U2;
  (float*) U3;

  (float*) S1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'struct Struct *' to 'float *'
  (float*) S2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefStruct *' to 'float *'
  (float*) S3; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingStruct *' to 'float *'

  (float*) C1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'class Class *' to 'float *'
  (float*) C2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefClass *' to 'float *'
  (float*) C3; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingClass *' to 'float *'

  reinterpret_cast<float*>(U1);
  reinterpret_cast<float*>(U2);
  reinterpret_cast<float*>(U3);

  reinterpret_cast<float*>(S1); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'struct Struct *' to 'float *'
  reinterpret_cast<float*>(S2); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefStruct *' to 'float *'
  reinterpret_cast<float*>(S3); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingStruct *' to 'float *'

  reinterpret_cast<float*>(C1); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'class Class *' to 'float *'
  reinterpret_cast<float*>(C2); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefClass *' to 'float *'
  reinterpret_cast<float*>(C3); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingClass *' to 'float *'

  (long*) U1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Union *' to 'long *'
  (long*) U2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnion *' to 'long *'
  (long*) U3; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingUnion *' to 'long *'

  (LongPtrTypedef) U1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Union *' to 'long *'
  (LongPtrTypedef) U2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnion *' to 'long *'
  (LongPtrTypedef) U3; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingUnion *' to 'long *'

  (LongPtrUsing) U1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Union *' to 'long *'
  (LongPtrUsing) U2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnion *' to 'long *'
  (LongPtrUsing) U3; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingUnion *' to 'long *'

  reinterpret_cast<long*>(U1); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Union *' to 'long *'
  reinterpret_cast<long*>(U2); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnion *' to 'long *'
  reinterpret_cast<long*>(U3); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingUnion *' to 'long *'

  reinterpret_cast<long*>(S1); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'struct Struct *' to 'long *'
  reinterpret_cast<long*>(S2); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefStruct *' to 'long *'
  reinterpret_cast<long*>(S3); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingStruct *' to 'long *'

  reinterpret_cast<long*>(C1); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'class Class *' to 'long *'
  reinterpret_cast<long*>(C2); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefClass *' to 'long *'
  reinterpret_cast<long*>(C3); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingClass *' to 'long *'

  reinterpret_cast<LongPtrTypedef>(U1); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Union *' to 'long *'
  reinterpret_cast<LongPtrTypedef>(U2); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnion *' to 'long *'
  reinterpret_cast<LongPtrTypedef>(U3); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingUnion *' to 'long *'

  reinterpret_cast<LongPtrTypedef>(S1); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'struct Struct *' to 'long *'
  reinterpret_cast<LongPtrTypedef>(S2); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefStruct *' to 'long *'
  reinterpret_cast<LongPtrTypedef>(S3); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingStruct *' to 'long *'

  reinterpret_cast<LongPtrTypedef>(C1); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'class Class *' to 'long *'
  reinterpret_cast<LongPtrTypedef>(C2); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefClass *' to 'long *'
  reinterpret_cast<LongPtrTypedef>(C3); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingClass *' to 'long *'

  reinterpret_cast<LongPtrUsing>(U1); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Union *' to 'long *'
  reinterpret_cast<LongPtrUsing>(U2); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnion *' to 'long *'
  reinterpret_cast<LongPtrUsing>(U3); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingUnion *' to 'long *'
 
  reinterpret_cast<LongPtrUsing>(S1); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'struct Struct *' to 'long *'
  reinterpret_cast<LongPtrUsing>(S2); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefStruct *' to 'long *'
  reinterpret_cast<LongPtrUsing>(S3); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingStruct *' to 'long *'

  reinterpret_cast<LongPtrUsing>(C1); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'class Class *' to 'long *'
  reinterpret_cast<LongPtrUsing>(C2); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefClass *' to 'long *'
  reinterpret_cast<LongPtrUsing>(C3); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingClass *' to 'long *'
  }

  /* fewer qualifiers are not accepted */
  {
  union Union { const volatile int i; };
  typedef union Union TypedefUnion;
  using UsingUnion = union Union;

  union Union  *U1;
  TypedefUnion *U2;
  UsingUnion   *U3;

  struct Struct { const volatile int i; };
  typedef struct Struct TypedefStruct;
  using UsingStruct = struct Struct;

  struct Struct *S1;
  TypedefStruct *S2;
  UsingStruct   *S3;

  class Class { const volatile int i; };
  typedef class Class TypedefClass;
  using UsingClass = class Class;

  class Class  *C1;
  TypedefClass *C2;
  UsingClass   *C3;

  (int*) U1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Union *' to 'int *'
  (int*) U2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnion *' to 'int *'
  (int*) U3; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingUnion *' to 'int *'

  (int*) S1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'struct Struct *' to 'int *'
  (int*) S2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefStruct *' to 'int *'
  (int*) S3; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingStruct *' to 'int *'

  (int*) C1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'class Class *' to 'int *'
  (int*) C2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefClass *' to 'int *'
  (int*) C3; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingClass *' to 'int *'

  reinterpret_cast<int*>(U1); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Union *' to 'int *'
  reinterpret_cast<int*>(U2); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnion *' to 'int *'
  reinterpret_cast<int*>(U3); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingUnion *' to 'int *'

  reinterpret_cast<int*>(S1); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'struct Struct *' to 'int *'
  reinterpret_cast<int*>(S2); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefStruct *' to 'int *'
  reinterpret_cast<int*>(S3); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingStruct *' to 'int *'

  reinterpret_cast<int*>(C1); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'class Class *' to 'int *'
  reinterpret_cast<int*>(C2); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefClass *' to 'int *'
  reinterpret_cast<int*>(C3); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingClass *' to 'int *'

  (const int*) U1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Union *' to 'const int *'
  (const int*) U2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnion *' to 'const int *'
  (const int*) U3; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingUnion *' to 'const int *'
                                                                                                               
  (const int*) S1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'struct Struct *' to 'const int *'
  (const int*) S2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefStruct *' to 'const int *'
  (const int*) S3; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingStruct *' to 'const int *'
                                                                                                              
  (const int*) C1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'class Class *' to 'const int *'
  (const int*) C2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefClass *' to 'const int *'
  (const int*) C3; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingClass *' to 'const int *'

  reinterpret_cast<const int*>(U1); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Union *' to 'const int *'
  reinterpret_cast<const int*>(U2); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnion *' to 'const int *'
  reinterpret_cast<const int*>(U3); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingUnion *' to 'const int *'
                                                                                                                                
  reinterpret_cast<const int*>(S1); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'struct Struct *' to 'const int *'
  reinterpret_cast<const int*>(S2); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefStruct *' to 'const int *'
  reinterpret_cast<const int*>(S3); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingStruct *' to 'const int *'
                                                                                                                               
  reinterpret_cast<const int*>(C1); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'class Class *' to 'const int *'
  reinterpret_cast<const int*>(C2); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefClass *' to 'const int *'
  reinterpret_cast<const int*>(C3); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingClass *' to 'const int *'

  (volatile int*) U1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Union *' to 'volatile int *'
  (volatile int*) U2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnion *' to 'volatile int *'
  (volatile int*) U3; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingUnion *' to 'volatile int *'
                                                                                                                  
  (volatile int*) S1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'struct Struct *' to 'volatile int *'
  (volatile int*) S2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefStruct *' to 'volatile int *'
  (volatile int*) S3; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingStruct *' to 'volatile int *'
                                                                                                                 
  (volatile int*) C1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'class Class *' to 'volatile int *'
  (volatile int*) C2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefClass *' to 'volatile int *'
  (volatile int*) C3; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingClass *' to 'volatile int *'

  reinterpret_cast<volatile int*>(U1); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Union *' to 'volatile int *'
  reinterpret_cast<volatile int*>(U2); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnion *' to 'volatile int *'
  reinterpret_cast<volatile int*>(U3); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingUnion *' to 'volatile int *'
                                                                                                                                   
  reinterpret_cast<volatile int*>(S1); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'struct Struct *' to 'volatile int *'
  reinterpret_cast<volatile int*>(S2); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefStruct *' to 'volatile int *'
  reinterpret_cast<volatile int*>(S3); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingStruct *' to 'volatile int *'
                                                                                                                                  
  reinterpret_cast<volatile int*>(C1); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'class Class *' to 'volatile int *'
  reinterpret_cast<volatile int*>(C2); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefClass *' to 'volatile int *'
  reinterpret_cast<volatile int*>(C3); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingClass *' to 'volatile int *'

  (const volatile int*) U1;
  (const volatile int*) U2;
  (const volatile int*) U3;

  (const volatile int*) S1;
  (const volatile int*) S2;
  (const volatile int*) S3;

  (const volatile int*) C1;
  (const volatile int*) C2;
  (const volatile int*) C3;

  reinterpret_cast<const volatile int*>(U1);
  reinterpret_cast<const volatile int*>(U2);
  reinterpret_cast<const volatile int*>(U3);

  reinterpret_cast<const volatile int*>(S1);
  reinterpret_cast<const volatile int*>(S2);
  reinterpret_cast<const volatile int*>(S3);

  reinterpret_cast<const volatile int*>(C1);
  reinterpret_cast<const volatile int*>(C2);
  reinterpret_cast<const volatile int*>(C3);
  }

  /*
   * default option behavior of AlwaysAllowCastToCharPtr
   */
  {
  union Union { const volatile int i; };
  typedef union Union TypedefUnion;
  using UsingUnion = union Union;

  union Union  *U1;
  TypedefUnion *U2;
  UsingUnion   *U3;

  struct Struct { const volatile int i; };
  typedef struct Struct TypedefStruct;
  using UsingStruct = struct Struct;

  struct Struct *S1;
  TypedefStruct *S2;
  UsingStruct   *S3;

  class Class { const volatile int i; };
  typedef class Class TypedefClass;
  using UsingClass = class Class;

  class Class  *C1;
  TypedefClass *C2;
  UsingClass   *C3;

  (char*) U1;
  (char*) U2;
  (char*) U3;
  (char*) S1;
  (char*) S2;
  (char*) S3;
  (char*) C1;
  (char*) C2;
  (char*) C3;

  (const char*) U1;
  (const char*) U2;
  (const char*) U3;
  (const char*) S1;
  (const char*) S2;
  (const char*) S3;
  (const char*) C1;
  (const char*) C2;
  (const char*) C3;

  (volatile char*) U1;
  (volatile char*) U2;
  (volatile char*) U3;
  (volatile char*) S1;
  (volatile char*) S2;
  (volatile char*) S3;
  (volatile char*) C1;
  (volatile char*) C2;
  (volatile char*) C3;

  (const volatile char*) U1;
  (const volatile char*) U2;
  (const volatile char*) U3;
  (const volatile char*) S1;
  (const volatile char*) S2;
  (const volatile char*) S3;
  (const volatile char*) C1;
  (const volatile char*) C2;
  (const volatile char*) C3;

  reinterpret_cast<char*>(U1);
  reinterpret_cast<char*>(U2);
  reinterpret_cast<char*>(U3);
  reinterpret_cast<char*>(S1);
  reinterpret_cast<char*>(S2);
  reinterpret_cast<char*>(S3);
  reinterpret_cast<char*>(C1);
  reinterpret_cast<char*>(C2);
  reinterpret_cast<char*>(C3);

  reinterpret_cast<const char*>(U1);
  reinterpret_cast<const char*>(U2);
  reinterpret_cast<const char*>(U3);
  reinterpret_cast<const char*>(S1);
  reinterpret_cast<const char*>(S2);
  reinterpret_cast<const char*>(S3);
  reinterpret_cast<const char*>(C1);
  reinterpret_cast<const char*>(C2);
  reinterpret_cast<const char*>(C3);

  reinterpret_cast<volatile char*>(U1);
  reinterpret_cast<volatile char*>(U2);
  reinterpret_cast<volatile char*>(U3);
  reinterpret_cast<volatile char*>(S1);
  reinterpret_cast<volatile char*>(S2);
  reinterpret_cast<volatile char*>(S3);
  reinterpret_cast<volatile char*>(C1);
  reinterpret_cast<volatile char*>(C2);
  reinterpret_cast<volatile char*>(C3);

  reinterpret_cast<const volatile char*>(U1);
  reinterpret_cast<const volatile char*>(U2);
  reinterpret_cast<const volatile char*>(U3);
  reinterpret_cast<const volatile char*>(S1);
  reinterpret_cast<const volatile char*>(S2);
  reinterpret_cast<const volatile char*>(S3);
  reinterpret_cast<const volatile char*>(C1);
  reinterpret_cast<const volatile char*>(C2);
  reinterpret_cast<const volatile char*>(C3);

  void *V;
  V = U1;
  V = U2;
  V = U3;
  V = S1;
  V = S2;
  V = S3;
  V = C1;
  V = C2;
  V = C3;

  const void *CV;
  CV = U1;
  CV = U2;
  CV = U3;
  CV = S1;
  CV = S2;
  CV = S3;
  CV = C1;
  CV = C2;
  CV = C3;

  volatile void *VV;
  VV = U1;
  VV = U2;
  VV = U3;
  VV = S1;
  VV = S2;
  VV = S3;
  VV = C1;
  VV = C2;
  VV = C3;

  const volatile void *CVV;
  CVV = U1;
  CVV = U2;
  CVV = U3;
  CVV = S1;
  CVV = S2;
  CVV = S3;
  CVV = C1;
  CVV = C2;
  CVV = C3;

  (void*) U1;
  (void*) U2;
  (void*) U3;
  (void*) S1;
  (void*) S2;
  (void*) S3;
  (void*) C1;
  (void*) C2;
  (void*) C3;

  (const void*) U1;
  (const void*) U2;
  (const void*) U3;
  (const void*) S1;
  (const void*) S2;
  (const void*) S3;
  (const void*) C1;
  (const void*) C2;
  (const void*) C3;

  (volatile void*) U1;
  (volatile void*) U2;
  (volatile void*) U3;
  (volatile void*) S1;
  (volatile void*) S2;
  (volatile void*) S3;
  (volatile void*) C1;
  (volatile void*) C2;
  (volatile void*) C3;

  (const volatile void*) U1;
  (const volatile void*) U2;
  (const volatile void*) U3;
  (const volatile void*) S1;
  (const volatile void*) S2;
  (const volatile void*) S3;
  (const volatile void*) C1;
  (const volatile void*) C2;
  (const volatile void*) C3;

  reinterpret_cast<void*>(U1);
  reinterpret_cast<void*>(U2);
  reinterpret_cast<void*>(U3);
  reinterpret_cast<void*>(S1);
  reinterpret_cast<void*>(S2);
  reinterpret_cast<void*>(S3);
  reinterpret_cast<void*>(C1);
  reinterpret_cast<void*>(C2);
  reinterpret_cast<void*>(C3);

  reinterpret_cast<const void*>(U1);
  reinterpret_cast<const void*>(U2);
  reinterpret_cast<const void*>(U3);
  reinterpret_cast<const void*>(S1);
  reinterpret_cast<const void*>(S2);
  reinterpret_cast<const void*>(S3);
  reinterpret_cast<const void*>(C1);
  reinterpret_cast<const void*>(C2);
  reinterpret_cast<const void*>(C3);

  reinterpret_cast<volatile void*>(U1);
  reinterpret_cast<volatile void*>(U2);
  reinterpret_cast<volatile void*>(U3);
  reinterpret_cast<volatile void*>(S1);
  reinterpret_cast<volatile void*>(S2);
  reinterpret_cast<volatile void*>(S3);
  reinterpret_cast<volatile void*>(C1);
  reinterpret_cast<volatile void*>(C2);
  reinterpret_cast<volatile void*>(C3);

  reinterpret_cast<const volatile void*>(U1);
  reinterpret_cast<const volatile void*>(U2);
  reinterpret_cast<const volatile void*>(U3);
  reinterpret_cast<const volatile void*>(S1);
  reinterpret_cast<const volatile void*>(S2);
  reinterpret_cast<const volatile void*>(S3);
  reinterpret_cast<const volatile void*>(C1);
  reinterpret_cast<const volatile void*>(C2);
  reinterpret_cast<const volatile void*>(C3);
  }

  /* Default behavior of options:
   * - IgnoreIfRecordIsFromStdNamespace
   * - IgnoreIfRecordIsFromSystemHeader
   */
  {
    std::pthread_mutex_t *T1;
    (double*) T1;
    reinterpret_cast<double*>(T1);

    pthread_mutex_t *T2;
    (double*) T2;
    reinterpret_cast<double*>(T2);
  }

  /* CompareCanonicalTypes option default behavior */
  {
  typedef int TypedefInt;
  typedef short *ShortPtrTypedef;
  typedef ShortPtrTypedef ShortPtrTypedefTypedef;
  typedef ShortPtrTypedef *ShortPtrTypedefPtr;
  typedef long *LongPtrTypedef;

  using ShortPtrUsing = short*;
  using ShortPtrUsingUsing = ShortPtrUsing;
  using ShortPtrUsingPtr = ShortPtrUsing*;

  union Union {
    TypedefInt i;
    short S;
    ShortPtrTypedef SPT;
    ShortPtrUsing SPU;
  };
  typedef union Union TypedefUnion;
  using UsingUnion = union Union;

  union Union  *U1;
  TypedefUnion *U2;
  UsingUnion   *U3;

  struct Struct { union Union U; };
  typedef struct Struct TypedefStruct;
  using UsingStruct = struct Struct;

  struct Struct *S1;
  TypedefStruct *S2;
  UsingStruct   *S3;

  class Class { union Union U; };
  typedef class Class TypedefClass;
  using UsingClass = class Class;

  class Class  *C1;
  TypedefClass *C2;
  UsingClass   *C3;

  (int*) U1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Union *' to 'int *'
  (int*) U2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnion *' to 'int *'
  (int*) U3; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingUnion *' to 'int *'

  (int*) S1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'struct Struct *' to 'int *'
  (int*) S2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefStruct *' to 'int *'
  (int*) S3; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingStruct *' to 'int *'

  (int*) C1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'class Class *' to 'int *'
  (int*) C2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefClass *' to 'int *'
  (int*) C3; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingClass *' to 'int *'

  reinterpret_cast<int*>(U1); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Union *' to 'int *'
  reinterpret_cast<int*>(U2); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnion *' to 'int *'
  reinterpret_cast<int*>(U3); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingUnion *' to 'int *'

  reinterpret_cast<int*>(S1); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'struct Struct *' to 'int *'
  reinterpret_cast<int*>(S2); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefStruct *' to 'int *'
  reinterpret_cast<int*>(S3); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingStruct *' to 'int *'

  reinterpret_cast<int*>(C1); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'class Class *' to 'int *'
  reinterpret_cast<int*>(C2); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefClass *' to 'int *'
  reinterpret_cast<int*>(C3); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingClass *' to 'int *'

  (ShortPtrTypedef) U1;
  (ShortPtrTypedef*) U1;
  (ShortPtrTypedefPtr) U1;
  (ShortPtrTypedefTypedef) U1;
  (ShortPtrUsing) U1;
  (ShortPtrUsing*) U1;
  (ShortPtrUsingUsing) U1;

  (ShortPtrTypedef) U2;
  (ShortPtrTypedef*) U2;
  (ShortPtrTypedefPtr) U2;
  (ShortPtrTypedefTypedef) U2;
  (ShortPtrUsing) U2;
  (ShortPtrUsing*) U2;
  (ShortPtrUsingUsing) U2;

  (ShortPtrTypedef) U3;
  (ShortPtrTypedef*) U3;
  (ShortPtrTypedefPtr) U3;
  (ShortPtrTypedefTypedef) U3;
  (ShortPtrUsing) U3;
  (ShortPtrUsing*) U3;
  (ShortPtrUsingUsing) U3;

  (ShortPtrTypedef) S1;
  (ShortPtrTypedef*) S1;
  (ShortPtrTypedefPtr) S1;
  (ShortPtrTypedefTypedef) S1;
  (ShortPtrUsing) S1;
  (ShortPtrUsing*) S1;
  (ShortPtrUsingUsing) S1;

  (ShortPtrTypedef) S2;
  (ShortPtrTypedef*) S2;
  (ShortPtrTypedefPtr) S2;
  (ShortPtrTypedefTypedef) S2;
  (ShortPtrUsing) S2;
  (ShortPtrUsing*) S2;
  (ShortPtrUsingUsing) S2;

  (ShortPtrTypedef) S3;
  (ShortPtrTypedef*) S3;
  (ShortPtrTypedefPtr) S3;
  (ShortPtrTypedefTypedef) S3;
  (ShortPtrUsing) S3;
  (ShortPtrUsing*) S3;
  (ShortPtrUsingUsing) S3;

  (ShortPtrTypedef) C1;
  (ShortPtrTypedef*) C1;
  (ShortPtrTypedefPtr) C1;
  (ShortPtrTypedefTypedef) C1;
  (ShortPtrUsing) C1;
  (ShortPtrUsing*) C1;
  (ShortPtrUsingUsing) C1;

  (ShortPtrTypedef) C2;
  (ShortPtrTypedef*) C2;
  (ShortPtrTypedefPtr) C2;
  (ShortPtrTypedefTypedef) C2;
  (ShortPtrUsing) C2;
  (ShortPtrUsing*) C2;
  (ShortPtrUsingUsing) C2;

  (ShortPtrTypedef) C3;
  (ShortPtrTypedef*) C3;
  (ShortPtrTypedefPtr) C3;
  (ShortPtrTypedefTypedef) C3;
  (ShortPtrUsing) C3;
  (ShortPtrUsing*) C3;
  (ShortPtrUsingUsing) C3;

  reinterpret_cast<ShortPtrTypedef>(U1);
  reinterpret_cast<ShortPtrTypedef*>(U1);
  reinterpret_cast<ShortPtrTypedefPtr>(U1);
  reinterpret_cast<ShortPtrTypedefTypedef>(U1);
  reinterpret_cast<ShortPtrUsing>(U1);
  reinterpret_cast<ShortPtrUsing*>(U1);
  reinterpret_cast<ShortPtrUsingUsing>(U1);

  reinterpret_cast<ShortPtrTypedef>(U2);
  reinterpret_cast<ShortPtrTypedef*>(U2);
  reinterpret_cast<ShortPtrTypedefPtr>(U2);
  reinterpret_cast<ShortPtrTypedefTypedef>(U2);
  reinterpret_cast<ShortPtrUsing>(U2);
  reinterpret_cast<ShortPtrUsing*>(U2);
  reinterpret_cast<ShortPtrUsingUsing>(U2);

  reinterpret_cast<ShortPtrTypedef>(U3);
  reinterpret_cast<ShortPtrTypedef*>(U3);
  reinterpret_cast<ShortPtrTypedefPtr>(U3);
  reinterpret_cast<ShortPtrTypedefTypedef>(U3);
  reinterpret_cast<ShortPtrUsing>(U3);
  reinterpret_cast<ShortPtrUsing*>(U3);
  reinterpret_cast<ShortPtrUsingUsing>(U3);

  reinterpret_cast<ShortPtrTypedef>(S1);
  reinterpret_cast<ShortPtrTypedef*>(S1);
  reinterpret_cast<ShortPtrTypedefPtr>(S1);
  reinterpret_cast<ShortPtrTypedefTypedef>(S1);
  reinterpret_cast<ShortPtrUsing>(S1);
  reinterpret_cast<ShortPtrUsing*>(S1);
  reinterpret_cast<ShortPtrUsingUsing>(S1);

  reinterpret_cast<ShortPtrTypedef>(S2);
  reinterpret_cast<ShortPtrTypedef*>(S2);
  reinterpret_cast<ShortPtrTypedefPtr>(S2);
  reinterpret_cast<ShortPtrTypedefTypedef>(S2);
  reinterpret_cast<ShortPtrUsing>(S2);
  reinterpret_cast<ShortPtrUsing*>(S2);
  reinterpret_cast<ShortPtrUsingUsing>(S2);

  reinterpret_cast<ShortPtrTypedef>(S3);
  reinterpret_cast<ShortPtrTypedef*>(S3);
  reinterpret_cast<ShortPtrTypedefPtr>(S3);
  reinterpret_cast<ShortPtrTypedefTypedef>(S3);
  reinterpret_cast<ShortPtrUsing>(S3);
  reinterpret_cast<ShortPtrUsing*>(S3);
  reinterpret_cast<ShortPtrUsingUsing>(S3);

  reinterpret_cast<ShortPtrTypedef>(C1);
  reinterpret_cast<ShortPtrTypedef*>(C1);
  reinterpret_cast<ShortPtrTypedefPtr>(C1);
  reinterpret_cast<ShortPtrTypedefTypedef>(C1);
  reinterpret_cast<ShortPtrUsing>(C1);
  reinterpret_cast<ShortPtrUsing*>(C1);
  reinterpret_cast<ShortPtrUsingUsing>(C1);

  reinterpret_cast<ShortPtrTypedef>(C2);
  reinterpret_cast<ShortPtrTypedef*>(C2);
  reinterpret_cast<ShortPtrTypedefPtr>(C2);
  reinterpret_cast<ShortPtrTypedefTypedef>(C2);
  reinterpret_cast<ShortPtrUsing>(C2);
  reinterpret_cast<ShortPtrUsing*>(C2);
  reinterpret_cast<ShortPtrUsingUsing>(C2);

  reinterpret_cast<ShortPtrTypedef>(C3);
  reinterpret_cast<ShortPtrTypedef*>(C3);
  reinterpret_cast<ShortPtrTypedefPtr>(C3);
  reinterpret_cast<ShortPtrTypedefTypedef>(C3);
  reinterpret_cast<ShortPtrUsing>(C3);
  reinterpret_cast<ShortPtrUsing*>(C3);
  reinterpret_cast<ShortPtrUsingUsing>(C3);
  }

  /* Cast to subobject type tests */
  {
  class Bar {
    float F;
  };
  
  struct Foo {
    class Bar B;
    int I;
  };

  union Union { struct Foo F; };
  typedef union Union TypedefUnion;
  using UsingUnion = union Union;

  union Union  *U1;
  TypedefUnion *U2;
  UsingUnion   *U3;

  struct Struct { struct Foo F; };
  typedef struct Struct TypedefStruct;
  using UsingStruct = struct Struct;

  struct Struct *S1;
  TypedefStruct *S2;
  UsingStruct   *S3;

  class Class { struct Foo F; };
  typedef class Class TypedefClass;
  using UsingClass = class Class;

  class Class  *C1;
  TypedefClass *C2;
  UsingClass   *C3;

  (Foo*) U1;
  (Foo*) U2;
  (Foo*) U3;
  (Foo*) S1;
  (Foo*) S2;
  (Foo*) S3;
  (Foo*) C1;
  (Foo*) C2;
  (Foo*) C3;
  reinterpret_cast<Foo*>(U1);
  reinterpret_cast<Foo*>(U2);
  reinterpret_cast<Foo*>(U3);
  reinterpret_cast<Foo*>(S1);
  reinterpret_cast<Foo*>(S2);
  reinterpret_cast<Foo*>(S3);
  reinterpret_cast<Foo*>(C1);
  reinterpret_cast<Foo*>(C2);
  reinterpret_cast<Foo*>(C3);

  (struct Foo*) U1;
  (struct Foo*) U2;
  (struct Foo*) U3;
  (struct Foo*) S1;
  (struct Foo*) S2;
  (struct Foo*) S3;
  (struct Foo*) C1;
  (struct Foo*) C2;
  (struct Foo*) C3;
  reinterpret_cast<struct Foo*>(U1);
  reinterpret_cast<struct Foo*>(U2);
  reinterpret_cast<struct Foo*>(U3);
  reinterpret_cast<struct Foo*>(S1);
  reinterpret_cast<struct Foo*>(S2);
  reinterpret_cast<struct Foo*>(S3);
  reinterpret_cast<struct Foo*>(C1);
  reinterpret_cast<struct Foo*>(C2);
  reinterpret_cast<struct Foo*>(C3);

  (Bar*) U1;
  (Bar*) U2;
  (Bar*) U3;
  (Bar*) S1;
  (Bar*) S2;
  (Bar*) S3;
  (Bar*) C1;
  (Bar*) C2;
  (Bar*) C3;
  reinterpret_cast<Bar*>(U1);
  reinterpret_cast<Bar*>(U2);
  reinterpret_cast<Bar*>(U3);
  reinterpret_cast<Bar*>(S1);
  reinterpret_cast<Bar*>(S2);
  reinterpret_cast<Bar*>(S3);
  reinterpret_cast<Bar*>(C1);
  reinterpret_cast<Bar*>(C2);
  reinterpret_cast<Bar*>(C3);

  (class Bar*) U1;
  (class Bar*) U2;
  (class Bar*) U3;
  (class Bar*) S1;
  (class Bar*) S2;
  (class Bar*) S3;
  (class Bar*) C1;
  (class Bar*) C2;
  (class Bar*) C3;
  reinterpret_cast<class Bar*>(U1);
  reinterpret_cast<class Bar*>(U2);
  reinterpret_cast<class Bar*>(U3);
  reinterpret_cast<class Bar*>(S1);
  reinterpret_cast<class Bar*>(S2);
  reinterpret_cast<class Bar*>(S3);
  reinterpret_cast<class Bar*>(C1);
  reinterpret_cast<class Bar*>(C2);
  reinterpret_cast<class Bar*>(C3);

  (float*) U1;
  (float*) U2;
  (float*) U3;

  (float*) S1;
  (float*) S2;
  (float*) S3;

  (float*) C1;
  (float*) C2;
  (float*) C3;

  reinterpret_cast<float*>(U1);
  reinterpret_cast<float*>(U2);
  reinterpret_cast<float*>(U3);

  reinterpret_cast<float*>(S1);
  reinterpret_cast<float*>(S2);
  reinterpret_cast<float*>(S3);

  reinterpret_cast<float*>(C1);
  reinterpret_cast<float*>(C2);
  reinterpret_cast<float*>(C3);

  (int*) U1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Union *' to 'int *'
  (int*) U2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnion *' to 'int *'
  (int*) U3; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingUnion *' to 'int *'

  (int*) S1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'struct Struct *' to 'int *'
  (int*) S2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefStruct *' to 'int *'
  (int*) S3; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingStruct *' to 'int *'

  (int*) C1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'class Class *' to 'int *'
  (int*) C2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefClass *' to 'int *'
  (int*) C3; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingClass *' to 'int *'

  reinterpret_cast<int*>(U1); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Union *' to 'int *'
  reinterpret_cast<int*>(U2); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnion *' to 'int *'
  reinterpret_cast<int*>(U3); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingUnion *' to 'int *'

  reinterpret_cast<int*>(S1); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'struct Struct *' to 'int *'
  reinterpret_cast<int*>(S2); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefStruct *' to 'int *'
  reinterpret_cast<int*>(S3); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingStruct *' to 'int *'

  reinterpret_cast<int*>(C1); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'class Class *' to 'int *'
  reinterpret_cast<int*>(C2); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefClass *' to 'int *'
  reinterpret_cast<int*>(C3); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingClass *' to 'int *'
  }

  /* Cast to base class of subobject */
  {
  class Base { int I; };
  class PublicDerived : public Base { };
  class PublicDerived2 : public PublicDerived { };

  union Union { PublicDerived2 D; };
  typedef union Union TypedefUnion;
  using UsingUnion = union Union;

  union Union  *U1;
  TypedefUnion *U2;
  UsingUnion   *U3;

  struct Struct { PublicDerived2 D; };
  typedef struct Struct TypedefStruct;
  using UsingStruct = struct Struct;

  struct Struct *S1;
  TypedefStruct *S2;
  UsingStruct   *S3;

  class Class { PublicDerived2 D; };
  typedef class Class TypedefClass;
  using UsingClass = class Class;

  class Class  *C1;
  TypedefClass *C2;
  UsingClass   *C3;

  (Base*) U1;
  (Base*) U2;
  (Base*) U3;
  reinterpret_cast<Base*>(U1);
  reinterpret_cast<Base*>(U2);
  reinterpret_cast<Base*>(U3);

  (Base*) S1;
  (Base*) S2;
  (Base*) S3;
  reinterpret_cast<Base*>(S1);
  reinterpret_cast<Base*>(S2);
  reinterpret_cast<Base*>(S3);

  (Base*) C1;
  (Base*) C2;
  (Base*) C3;
  reinterpret_cast<Base*>(C1);
  reinterpret_cast<Base*>(C2);
  reinterpret_cast<Base*>(C3);
  }

  /* Non standard-layout test cases */
  {
  // Has virtual methods (and a vtable as a result)
  struct Struct { virtual void foo() { } };
  typedef struct Struct TypedefStruct;
  using UsingStruct = struct Struct;

  struct Struct *S1;
  TypedefStruct *S2;
  UsingStruct   *S3;

  class Base { int I; }; 
  // Not all subobjects of Class are defined in the same class
  class Class : public Base { int I; };
  typedef class Class TypedefClass;
  using UsingClass = class Class;

  class Class  *C1;
  TypedefClass *C2;
  UsingClass   *C3;

  // Contains non standard-layout member
  union Union { class Class C; };
  typedef union Union TypedefUnion;
  using UsingUnion = union Union;

  union Union  *U1;
  TypedefUnion *U2;
  UsingUnion   *U3;

  (int*) U1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Union *' to 'int *'
  (int*) U2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnion *' to 'int *'
  (int*) U3; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingUnion *' to 'int *'

  (int*) S1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'struct Struct *' to 'int *'
  (int*) S2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefStruct *' to 'int *'
  (int*) S3; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingStruct *' to 'int *'

  (int*) C1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'class Class *' to 'int *'
  (int*) C2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefClass *' to 'int *'
  (int*) C3; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingClass *' to 'int *'

  reinterpret_cast<int*>(U1); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Union *' to 'int *'
  reinterpret_cast<int*>(U2); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnion *' to 'int *'
  reinterpret_cast<int*>(U3); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingUnion *' to 'int *'

  reinterpret_cast<int*>(S1); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'struct Struct *' to 'int *'
  reinterpret_cast<int*>(S2); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefStruct *' to 'int *'
  reinterpret_cast<int*>(S3); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingStruct *' to 'int *'

  reinterpret_cast<int*>(C1); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'class Class *' to 'int *'
  reinterpret_cast<int*>(C2); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefClass *' to 'int *'
  reinterpret_cast<int*>(C3); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingClass *' to 'int *'

  }

  /*
   * Casting pointer to record which has no definition is disallowed, except to
   * char* and void*.
   */
  {
  union Union;
  typedef union Union TypedefUnion;
  using UsingUnion = union Union;

  union Union  *U1;
  TypedefUnion *U2;
  UsingUnion   *U3;

  struct Struct;
  typedef struct Struct TypedefStruct;
  using UsingStruct = struct Struct;

  struct Struct *S1;
  TypedefStruct *S2;
  UsingStruct   *S3;

  class Class;
  typedef class Class TypedefClass;
  using UsingClass = class Class;

  class Class  *C1;
  TypedefClass *C2;
  UsingClass   *C3;

  (char*) U1;
  (char*) U2;
  (char*) U3;

  (char*) S1;
  (char*) S2;
  (char*) S3;

  (char*) C1;
  (char*) C2;
  (char*) C3;

  reinterpret_cast<char*>(U1);
  reinterpret_cast<char*>(U2);
  reinterpret_cast<char*>(U3);

  reinterpret_cast<char*>(S1);
  reinterpret_cast<char*>(S2);
  reinterpret_cast<char*>(S3);

  reinterpret_cast<char*>(C1);
  reinterpret_cast<char*>(C2);
  reinterpret_cast<char*>(C3);

  (void*) U1;
  (void*) U2;
  (void*) U3;

  (void*) S1;
  (void*) S2;
  (void*) S3;

  (void*) C1;
  (void*) C2;
  (void*) C3;

  reinterpret_cast<void*>(U1);
  reinterpret_cast<void*>(U2);
  reinterpret_cast<void*>(U3);

  reinterpret_cast<void*>(S1);
  reinterpret_cast<void*>(S2);
  reinterpret_cast<void*>(S3);

  reinterpret_cast<void*>(C1);
  reinterpret_cast<void*>(C2);
  reinterpret_cast<void*>(C3);

  (int*) U1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Union *' to 'int *'
  (int*) U2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnion *' to 'int *'
  (int*) U3; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingUnion *' to 'int *'

  (int*) S1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'struct Struct *' to 'int *'
  (int*) S2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefStruct *' to 'int *'
  (int*) S3; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingStruct *' to 'int *'

  (int*) C1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'class Class *' to 'int *'
  (int*) C2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefClass *' to 'int *'
  (int*) C3; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingClass *' to 'int *'

  reinterpret_cast<int*>(U1); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Union *' to 'int *'
  reinterpret_cast<int*>(U2); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnion *' to 'int *'
  reinterpret_cast<int*>(U3); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingUnion *' to 'int *'

  reinterpret_cast<int*>(S1); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'struct Struct *' to 'int *'
  reinterpret_cast<int*>(S2); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefStruct *' to 'int *'
  reinterpret_cast<int*>(S3); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingStruct *' to 'int *'

  reinterpret_cast<int*>(C1); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'class Class *' to 'int *'
  reinterpret_cast<int*>(C2); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefClass *' to 'int *'
  reinterpret_cast<int*>(C3); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingClass *' to 'int *'
  }
}
