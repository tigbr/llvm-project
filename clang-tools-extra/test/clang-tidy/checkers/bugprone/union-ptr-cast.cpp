// RUN: %check_clang_tidy -std=c++98-or-later %s bugprone-union-ptr-cast %t -- -- \
// RUN: -I%S/Inputs/union-ptr-cast \
// RUN: -isystem %S/Inputs/union-ptr-cast/system

typedef short *ShortPtrTypedef;
typedef ShortPtrTypedef ShortPtrTypedefTypedef;
typedef ShortPtrTypedef *ShortPtrTypedefPtr;
typedef long *LongPtrTypedef;

using ShortPtrUsing = short*;
using ShortPtrUsingUsing = ShortPtrUsing;
using ShortPtrUsingPtr = ShortPtrUsing*;
using LongPtrUsing = long*;

struct NotStandardLayoutStruct {
  int x;
  virtual void foo() { }
};

typedef NotStandardLayoutStruct TypedefNotStandardLayoutStruct;
using UsingNotStandardLayoutStruct = NotStandardLayoutStruct;

struct HasNonStandardLayoutFirstMemberDirectly {
  struct NotStandardLayoutStruct s;
};

struct HasNonStandardLayout {
  struct NotStandardLayoutStruct s;
};

struct HasNonStandardLayoutFirstMemberIndirectly {
  struct HasNonStandardLayout s;
};

struct Bar {
  void *F1;
};

struct Foo {
  struct Bar F1;
  void **F2;
};

struct BarStruct { int i; };
class BarClass { int i; };
union BarUnion { int i; };
enum BarEnum { BarEnumVal };

union FooBar {
  struct Foo F1;
  double **F2;
};

class Base { int I; };
class PublicDerived : public Base { };
class ProtectedDerived : protected Base { };
class PrivateDerived : private Base { };
class PublicDerived2 : public PublicDerived { };
class PublicDerived3 : public PublicDerived2 { };

union MyUnion {
  volatile int *F1;
  const int *F2;
  const volatile int *F3;
  short F4;
  float F5;
  ShortPtrTypedef F6;
  union FooBar F7;
  ShortPtrUsing F8;
  PublicDerived F9;
  ProtectedDerived F10;
  PrivateDerived F11;
  PublicDerived2 F12;
  PublicDerived3 F13;
  struct BarStruct F14;
  union BarUnion F15;
  enum BarEnum F16;
  class BarClass F17;
};

typedef union MyUnion TypedefMyUnion;
using UsingMyUnion = union MyUnion;

void castToTypeInUnion(union MyUnion *U, TypedefMyUnion *TU, UsingMyUnion *UU) {
  (volatile int**) U;
  (const int**) U;
  (const volatile int**) U;
  (short*) U;
  (float*) U;
  (PublicDerived*) U;
  (ProtectedDerived*) U;
  (PrivateDerived*) U;
  (PublicDerived2*) U;
  (PublicDerived3*) U;
  (struct BarStruct*) U;
  (class BarClass*) U;
  (union BarUnion*) U;
  (enum BarEnum*) U;
  (BarStruct*) U;
  (BarClass*) U;
  (BarUnion*) U;
  (BarEnum*) U;

  (volatile int**) TU;
  (const int**) TU;
  (const volatile int**) TU;
  (short*) TU;
  (float*) TU;
  (PublicDerived*) TU;
  (ProtectedDerived*) TU;
  (PrivateDerived*) TU;
  (PublicDerived2*) TU;
  (PublicDerived3*) TU;
  (struct BarStruct*) TU;
  (class BarClass*) TU;
  (union BarUnion*) TU;
  (enum BarEnum*) TU;
  (BarStruct*) TU;
  (BarClass*) TU;
  (BarUnion*) TU;
  (BarEnum*) TU;

  (volatile int**) UU;
  (const int**) UU;
  (const volatile int**) UU;
  (short*) UU;
  (float*) UU; 
  (PublicDerived*) UU;
  (ProtectedDerived*) UU;
  (PrivateDerived*) UU;
  (PublicDerived2*) UU;
  (PublicDerived3*) UU;
  (struct BarStruct*) UU;
  (class BarClass*) UU;
  (union BarUnion*) UU;
  (enum BarEnum*) UU;
  (BarStruct*) UU;
  (BarClass*) UU;
  (BarUnion*) UU;
  (BarEnum*) UU;

  reinterpret_cast<volatile int**>(U);
  reinterpret_cast<const int**>(U);
  reinterpret_cast<const volatile int**>(U);
  reinterpret_cast<short*>(U);
  reinterpret_cast<float*>(U);
  reinterpret_cast<PublicDerived*>(U);
  reinterpret_cast<ProtectedDerived*>(U);
  reinterpret_cast<PrivateDerived*>(U);
  reinterpret_cast<PublicDerived2*>(U);
  reinterpret_cast<PublicDerived3*>(U);

  reinterpret_cast<volatile int**>(TU);
  reinterpret_cast<const int**>(TU);
  reinterpret_cast<const volatile int**>(TU);
  reinterpret_cast<short*>(TU);
  reinterpret_cast<float*>(TU);
  reinterpret_cast<PublicDerived*>(TU);
  reinterpret_cast<ProtectedDerived*>(TU);
  reinterpret_cast<PrivateDerived*>(TU);
  reinterpret_cast<PublicDerived2*>(TU);
  reinterpret_cast<PublicDerived3*>(TU);

  reinterpret_cast<volatile int**>(UU);
  reinterpret_cast<const int**>(UU);
  reinterpret_cast<const volatile int**>(UU);
  reinterpret_cast<short*>(UU);
  reinterpret_cast<float*>(UU);
  reinterpret_cast<PublicDerived*>(UU);
  reinterpret_cast<ProtectedDerived*>(UU);
  reinterpret_cast<PrivateDerived*>(UU);
  reinterpret_cast<PublicDerived2*>(UU);
  reinterpret_cast<PublicDerived3*>(UU);
}

#include "stdnamespace.h"
#include <pthread.h>

void optionDependentDefaultBehaviors(union MyUnion *U, TypedefMyUnion *TU, UsingMyUnion *UU, NotStandardLayoutStruct *S, TypedefNotStandardLayoutStruct *TS, UsingNotStandardLayoutStruct *US) {

  /* AllowCastToBaseClass */
  union { PublicDerived  field; } *U1;
  typedef union { PublicDerived  field; } TypedefU1;
  TypedefU1 *TU1;
  using UsingU1 = union { PublicDerived  field; };
  UsingU1 *UU1;
  (Base*) U1;
  (Base*) TU1;
  (Base*) UU1;
  reinterpret_cast<Base*>(U1);
  reinterpret_cast<Base*>(TU1);
  reinterpret_cast<Base*>(UU1);

  union { PublicDerived2 field; } *U2;
  typedef union { PublicDerived2 field; } TypedefU2;
  TypedefU2 *TU2;
  using UsingU2 = union { PublicDerived2 field; };
  UsingU2 *UU2;
  (Base*) U2;
  (Base*) TU2;
  (Base*) UU2;
  reinterpret_cast<Base*>(U2);
  reinterpret_cast<Base*>(TU2);
  reinterpret_cast<Base*>(UU2);

  union { PublicDerived3 field; } *U3;
  typedef union { PublicDerived3 field; } TypedefU3;
  TypedefU3 *TU3;
  using UsingU3 = union { PublicDerived3 field; };
  UsingU3 *UU3;
  (Base*) U3;
  (Base*) TU3;
  (Base*) UU3;
  reinterpret_cast<Base*>(U3);
  reinterpret_cast<Base*>(TU3);
  reinterpret_cast<Base*>(UU3);

  union { ProtectedDerived field; } *U4;
  typedef union { PublicDerived3 field; } TypedefU4;
  TypedefU4 *TU4;
  using UsingU4 = union { PublicDerived3 field; };
  UsingU4 *UU4;
  (Base*) U4;
  (Base*) TU4;
  (Base*) UU4;
  reinterpret_cast<Base*>(U4);
  reinterpret_cast<Base*>(TU4);
  reinterpret_cast<Base*>(UU4);

  union { PrivateDerived field; } *U5;
  typedef union { PrivateDerived field; } TypedefU5;
  TypedefU5 *TU5;
  using UsingU5 = union { PrivateDerived field; };
  UsingU5 *UU5;
  (Base*) U5;
  (Base*) TU5;
  (Base*) UU5;
  reinterpret_cast<Base*>(U5);
  reinterpret_cast<Base*>(TU5);
  reinterpret_cast<Base*>(UU5);

  /* AllowCastToSubField */
  (Foo*) U;
  (Foo*) TU;
  (Foo*) UU;
  reinterpret_cast<Foo*>(U);
  reinterpret_cast<Foo*>(TU);
  reinterpret_cast<Foo*>(UU);

  (struct Foo*) U;
  (struct Foo*) TU;
  (struct Foo*) UU;
  reinterpret_cast<struct Foo*>(U);
  reinterpret_cast<struct Foo*>(TU);
  reinterpret_cast<struct Foo*>(UU);

  (double***) U;
  (double***) TU;
  (double***) UU;
  reinterpret_cast<double***>(U);
  reinterpret_cast<double***>(TU);
  reinterpret_cast<double***>(UU);

  (Bar*) U;
  (Bar*) TU;
  (Bar*) UU;
  reinterpret_cast<Bar*>(U);
  reinterpret_cast<Bar*>(TU);
  reinterpret_cast<Bar*>(UU);

  (struct Bar*) U;
  (struct Bar*) TU;
  (struct Bar*) UU;
  reinterpret_cast<struct Bar*>(U);
  reinterpret_cast<struct Bar*>(TU);
  reinterpret_cast<struct Bar*>(UU);

  (void ***) U;      // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union MyUnion *' to 'void ***'
  (void ***) TU;     // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefMyUnion *' to 'void ***'
  (void ***) UU;     // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingMyUnion *' to 'void ***'
  reinterpret_cast<void ***>(U);  // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union MyUnion *' to 'void ***'
  reinterpret_cast<void ***>(TU); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefMyUnion *' to 'void ***'
  reinterpret_cast<void ***>(UU); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingMyUnion *' to 'void ***'

  (void **) U;
  (void **) TU;
  (void **) UU;
  reinterpret_cast<void **>(U);
  reinterpret_cast<void **>(TU);
  reinterpret_cast<void **>(UU);

  // Standard layout test cases
  NotStandardLayoutStruct *S1;
  HasNonStandardLayoutFirstMemberDirectly *S2;
  HasNonStandardLayoutFirstMemberIndirectly *S3;

  (int*) S1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'NotStandardLayoutStruct *' to 'int *'
  (int*) S2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'HasNonStandardLayoutFirstMemberDirectly *' to 'int *'
  (int*) S3; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'HasNonStandardLayoutFirstMemberIndirectly *' to 'int *'

  reinterpret_cast<int*>(S1); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'NotStandardLayoutStruct *' to 'int *'
  reinterpret_cast<int*>(S2); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'HasNonStandardLayoutFirstMemberDirectly *' to 'int *'
  reinterpret_cast<int*>(S3); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'HasNonStandardLayoutFirstMemberIndirectly *' to 'int *'

  /* AlwaysAllowCastToCharPtr */
  // Implicit casts to char* cause compile errors
  (char*) U;
  (char*) TU;
  (char*) UU;
  (const char*) U;
  (const char*) TU;
  (const char*) UU;
  (volatile char*) U;
  (volatile char*) TU;
  (volatile char*) UU;
  (volatile const char*) U;
  (volatile const char*) TU;
  (volatile const char*) UU;
  reinterpret_cast<char*>(U);
  reinterpret_cast<char*>(TU);
  reinterpret_cast<char*>(UU);
  reinterpret_cast<const char*>(U);
  reinterpret_cast<const char*>(TU);
  reinterpret_cast<const char*>(UU);
  reinterpret_cast<volatile char*>(U);
  reinterpret_cast<volatile char*>(TU);
  reinterpret_cast<volatile char*>(UU);
  reinterpret_cast<volatile const char*>(U);
  reinterpret_cast<volatile const char*>(TU);
  reinterpret_cast<volatile const char*>(UU);

  /* AlwaysAllowCastToVoidPtr */
  void *V;
  V = U;
  V = TU;
  V = UU;
  (void*) U;
  (void*) TU;
  (void*) UU;
  (const void*) U;
  (const void*) TU;
  (const void*) UU;
  (volatile void*) U;
  (volatile void*) TU;
  (volatile void*) UU;
  (volatile const void*) U;
  (volatile const void*) TU;
  (volatile const void*) UU;
  reinterpret_cast<void*>(U);
  reinterpret_cast<void*>(TU);
  reinterpret_cast<void*>(UU);
  reinterpret_cast<const void*>(U);
  reinterpret_cast<const void*>(TU);
  reinterpret_cast<const void*>(UU);
  reinterpret_cast<volatile void*>(U);
  reinterpret_cast<volatile void*>(TU);
  reinterpret_cast<volatile void*>(UU);
  reinterpret_cast<volatile const void*>(U);
  reinterpret_cast<volatile const void*>(TU);
  reinterpret_cast<volatile const void*>(UU);

  /* CompareCanonicalTypes */
  (ShortPtrTypedef) U;
  (ShortPtrTypedef*) U;
  (ShortPtrTypedefPtr) U;
  (ShortPtrTypedefTypedef) U;
  (ShortPtrUsing) U;
  (ShortPtrUsing*) U;
  (ShortPtrUsingUsing) U;

  (ShortPtrTypedef) TU;
  (ShortPtrTypedef*) TU;
  (ShortPtrTypedefPtr) TU;
  (ShortPtrTypedefTypedef) TU;
  (ShortPtrUsing) TU;
  (ShortPtrUsing*) TU;
  (ShortPtrUsingUsing) TU;

  (ShortPtrTypedef) UU;
  (ShortPtrTypedef*) UU;
  (ShortPtrTypedefPtr) UU;
  (ShortPtrTypedefTypedef) UU;
  (ShortPtrUsing) UU;
  (ShortPtrUsing*) UU;
  (ShortPtrUsingUsing) UU;

  reinterpret_cast<ShortPtrTypedef>(U);
  reinterpret_cast<ShortPtrTypedef*>(U);
  reinterpret_cast<ShortPtrTypedefPtr>(U);
  reinterpret_cast<ShortPtrTypedefTypedef>(U);
  reinterpret_cast<ShortPtrUsing>(U);
  reinterpret_cast<ShortPtrUsing*>(U);
  reinterpret_cast<ShortPtrUsingUsing>(U);

  reinterpret_cast<ShortPtrTypedef>(TU);
  reinterpret_cast<ShortPtrTypedef*>(TU);
  reinterpret_cast<ShortPtrTypedefPtr>(TU);
  reinterpret_cast<ShortPtrTypedefTypedef>(TU);
  reinterpret_cast<ShortPtrUsing>(TU);
  reinterpret_cast<ShortPtrUsing*>(TU);
  reinterpret_cast<ShortPtrUsingUsing>(TU);

  reinterpret_cast<ShortPtrTypedef>(UU);
  reinterpret_cast<ShortPtrTypedef*>(UU);
  reinterpret_cast<ShortPtrTypedefPtr>(UU);
  reinterpret_cast<ShortPtrTypedefTypedef>(UU);
  reinterpret_cast<ShortPtrUsing>(UU);
  reinterpret_cast<ShortPtrUsing*>(UU);
  reinterpret_cast<ShortPtrUsingUsing>(UU);

  /* IgnoreIfUnionIsFromStdNamespace */
  std::pthread_mutex_t *T1;
  (double*) T1;
  reinterpret_cast<double*>(T1);

  /* IgnoreIfUnionIsFromSystemHeader */
  pthread_mutex_t *T2;
  (double*) T2;
  reinterpret_cast<double*>(T2);
}

void doNotWarnAboutThese(union MyUnion *U, TypedefMyUnion *TU, UsingMyUnion *UU) {
  long LI;
  unsigned long UL = LI;
  (unsigned long) LI;
  // This is already a compile time error.
  // reinterpret_cast<unsigned long>(LI);

  (void*) LI;
  reinterpret_cast<void*>(LI);

  // Zero instead of nullptr, because the latter exists only from C++11.
  Base *B = 0;
  PublicDerived *D = 0;

  B = B;
  (Base*) B;
  reinterpret_cast<Base*>(B);
  static_cast<Base*>(B);
  dynamic_cast<Base*>(B);

  B = D;
  (PublicDerived*) D;
  reinterpret_cast<PublicDerived*>(D);
  static_cast<PublicDerived*>(D);
  dynamic_cast<PublicDerived*>(D);

  B = D;
  (Base*) D;
  reinterpret_cast<Base*>(D);
  static_cast<Base*>(D);

  union MyUnion *MU = U;
  (union MyUnion*) U;
  reinterpret_cast<union MyUnion*>(U);

  TypedefMyUnion *MTU = TU;
  (TypedefMyUnion*) TU;
  reinterpret_cast<TypedefMyUnion*>(TU);

  UsingMyUnion *MUU = UU;
  (UsingMyUnion*) UU;
  reinterpret_cast<UsingMyUnion*>(UU);
}

void castsWithQualifierMismatches() {
  typedef union { char *Ptr; } TypedefU1;
  using UsingU1 = union { char *Ptr; };
  TypedefU1 *TU1;
  UsingU1 *UU1;
  union QTUnion1 { char *Ptr; } *U1;
  (volatile char**)       U1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union QTUnion1 *' to 'volatile char **'
  (const char**)          U1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union QTUnion1 *' to 'const char **'
  (const volatile char**) U1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union QTUnion1 *' to 'const volatile char **'
  reinterpret_cast<volatile char**>      (U1); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union QTUnion1 *' to 'volatile char **'
  reinterpret_cast<const char**>         (U1); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union QTUnion1 *' to 'const char **'
  reinterpret_cast<const volatile char**>(U1); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union QTUnion1 *' to 'const volatile char **'

  (volatile char**)       TU1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefU1 *' to 'volatile char **'
  (const char**)          TU1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefU1 *' to 'const char **'
  (const volatile char**) TU1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefU1 *' to 'const volatile char **'
  reinterpret_cast<volatile char**>      (TU1); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefU1 *' to 'volatile char **'
  reinterpret_cast<const char**>         (TU1); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefU1 *' to 'const char **'
  reinterpret_cast<const volatile char**>(TU1); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefU1 *' to 'const volatile char **'

  (volatile char**)       UU1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingU1 *' to 'volatile char **'
  (const char**)          UU1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingU1 *' to 'const char **'
  (const volatile char**) UU1; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingU1 *' to 'const volatile char **'
  reinterpret_cast<volatile char**>      (UU1); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingU1 *' to 'volatile char **'
  reinterpret_cast<const char**>         (UU1); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingU1 *' to 'const char **'
  reinterpret_cast<const volatile char**>(UU1); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingU1 *' to 'const volatile char **'


  typedef union { const char *Ptr; } TypedefU2;
  using UsingU2 = union { const char *Ptr; };
  TypedefU2 *TU2;
  UsingU2 *UU2;
  union QTUnion2 { const char *Ptr; } *U2;
  (char**)                U2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union QTUnion2 *' to 'char **'
  (volatile char**)       U2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union QTUnion2 *' to 'volatile char **'
  (const volatile char**) U2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union QTUnion2 *' to 'const volatile char **'
  reinterpret_cast<char**>               (U2); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union QTUnion2 *' to 'char **'
  reinterpret_cast<volatile char**>      (U2); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union QTUnion2 *' to 'volatile char **'
  reinterpret_cast<const volatile char**>(U2); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union QTUnion2 *' to 'const volatile char **'

  (char**)                TU2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefU2 *' to 'char **'
  (volatile char**)       TU2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefU2 *' to 'volatile char **'
  (const volatile char**) TU2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefU2 *' to 'const volatile char **'
  reinterpret_cast<char**>               (TU2); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefU2 *' to 'char **'
  reinterpret_cast<volatile char**>      (TU2); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefU2 *' to 'volatile char **'
  reinterpret_cast<const volatile char**>(TU2); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefU2 *' to 'const volatile char **'

  (char**)                UU2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingU2 *' to 'char **'
  (volatile char**)       UU2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingU2 *' to 'volatile char **'
  (const volatile char**) UU2; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingU2 *' to 'const volatile char **'
  reinterpret_cast<char**>               (UU2); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingU2 *' to 'char **'
  reinterpret_cast<volatile char**>      (UU2); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingU2 *' to 'volatile char **'
  reinterpret_cast<const volatile char**>(UU2); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingU2 *' to 'const volatile char **'


  typedef union { volatile char *Ptr; } TypedefU3;
  using UsingU3 = union { volatile char *Ptr; };
  TypedefU3 *TU3;
  UsingU3 *UU3;
  union QTUnion3 { volatile char *Ptr; } *U3;
  (char**)                U3; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union QTUnion3 *' to 'char **'
  (const char**)          U3; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union QTUnion3 *' to 'const char **'
  (const volatile char**) U3; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union QTUnion3 *' to 'const volatile char **'
  reinterpret_cast<char**>               (U3); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union QTUnion3 *' to 'char **'
  reinterpret_cast<const char**>         (U3); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union QTUnion3 *' to 'const char **'
  reinterpret_cast<const volatile char**>(U3); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union QTUnion3 *' to 'const volatile char **'

  (char**)                TU3; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefU3 *' to 'char **'
  (const char**)          TU3; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefU3 *' to 'const char **'
  (const volatile char**) TU3; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefU3 *' to 'const volatile char **'
  reinterpret_cast<char**>               (TU3); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefU3 *' to 'char **'
  reinterpret_cast<const char**>         (TU3); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefU3 *' to 'const char **'
  reinterpret_cast<const volatile char**>(TU3); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefU3 *' to 'const volatile char **'

  (char**)                UU3; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingU3 *' to 'char **'
  (const char**)          UU3; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingU3 *' to 'const char **'
  (const volatile char**) UU3; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingU3 *' to 'const volatile char **'
  reinterpret_cast<char**>               (UU3); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingU3 *' to 'char **'
  reinterpret_cast<const char**>         (UU3); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingU3 *' to 'const char **'
  reinterpret_cast<const volatile char**>(UU3); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingU3 *' to 'const volatile char **'

  typedef union { const volatile char *Ptr; } TypedefU4;
  using UsingU4 = union { const volatile char *Ptr; };
  TypedefU4 *TU4;
  UsingU4 *UU4;
  union QTUnion4 { const volatile char *Ptr; } *U4;
  (char**)                U4; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union QTUnion4 *' to 'char **'
  (volatile char**)       U4; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union QTUnion4 *' to 'volatile char **'
  (const char**)          U4; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union QTUnion4 *' to 'const char **'
  reinterpret_cast<char**>               (U4); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union QTUnion4 *' to 'char **'
  reinterpret_cast<volatile char**>      (U4); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union QTUnion4 *' to 'volatile char **'
  reinterpret_cast<const char**>         (U4); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union QTUnion4 *' to 'const char **'

  (char**)                TU4; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefU4 *' to 'char **'
  (volatile char**)       TU4; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefU4 *' to 'volatile char **'
  (const char**)          TU4; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefU4 *' to 'const char **'
  reinterpret_cast<char**>               (TU4); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefU4 *' to 'char **'
  reinterpret_cast<volatile char**>      (TU4); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefU4 *' to 'volatile char **'
  reinterpret_cast<const char**>         (TU4); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefU4 *' to 'const char **'

  (char**)                UU4; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingU4 *' to 'char **'
  (volatile char**)       UU4; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingU4 *' to 'volatile char **'
  (const char**)          UU4; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingU4 *' to 'const char **'
  reinterpret_cast<char**>               (UU4); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingU4 *' to 'char **'
  reinterpret_cast<volatile char**>      (UU4); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingU4 *' to 'volatile char **'
  reinterpret_cast<const char**>         (UU4); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingU4 *' to 'const char **'
}

void castsToTypeWithNoCorresspondingFieldInUnion(union MyUnion *U, TypedefMyUnion *TU, UsingMyUnion *UU) {
  (long*) U; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union MyUnion *' to 'long *'
  (long*) TU; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefMyUnion *' to 'long *'
  (long*) UU; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingMyUnion *' to 'long *'

  (LongPtrTypedef) U; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union MyUnion *' to 'long *'
  (LongPtrTypedef) TU; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefMyUnion *' to 'long *'
  (LongPtrTypedef) UU; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingMyUnion *' to 'long *'

  (LongPtrUsing) U; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union MyUnion *' to 'long *'
  (LongPtrUsing) TU; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefMyUnion *' to 'long *'
  (LongPtrUsing) UU; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingMyUnion *' to 'long *'

  reinterpret_cast<long*>(U); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union MyUnion *' to 'long *'
  reinterpret_cast<long*>(TU); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefMyUnion *' to 'long *'
  reinterpret_cast<long*>(UU); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingMyUnion *' to 'long *'

  reinterpret_cast<LongPtrTypedef>(U); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union MyUnion *' to 'long *'
  reinterpret_cast<LongPtrTypedef>(TU); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefMyUnion *' to 'long *'
  reinterpret_cast<LongPtrTypedef>(UU); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingMyUnion *' to 'long *'

  reinterpret_cast<LongPtrUsing>(U); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union MyUnion *' to 'long *'
  reinterpret_cast<LongPtrUsing>(TU); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefMyUnion *' to 'long *'
  reinterpret_cast<LongPtrUsing>(UU); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingMyUnion *' to 'long *'
}

typedef union Unknown TypedefUnknown;
using UsingUnknown = union Unknown;

void castsWhenUnionDefinitionIsUnknown(union Unknown *U, TypedefUnknown *TU, UsingUnknown *UU) {
  (volatile char**)       U; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Unknown *' to 'volatile char **'
  (const char**)          U; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Unknown *' to 'const char **'
  (const volatile char**) U; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Unknown *' to 'const volatile char **'
  (short*)                U; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Unknown *' to 'short *'
  (int*)                  U; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Unknown *' to 'int *'
  (long*)                 U; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Unknown *' to 'long *'
  (float*)                U; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Unknown *' to 'float *'
  (double*)               U; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Unknown *' to 'double *'
  (PublicDerived*)        U; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Unknown *' to 'PublicDerived *'
  (ProtectedDerived*)     U; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Unknown *' to 'ProtectedDerived *'
  (PrivateDerived*)       U; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Unknown *' to 'PrivateDerived *'
  (PublicDerived2*)       U; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Unknown *' to 'PublicDerived2 *'
  (PublicDerived3*)       U; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Unknown *' to 'PublicDerived3 *'

  (volatile char**)       TU; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnknown *' to 'volatile char **'
  (const char**)          TU; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnknown *' to 'const char **'
  (const volatile char**) TU; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnknown *' to 'const volatile char **'
  (short*)                TU; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnknown *' to 'short *'
  (int*)                  TU; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnknown *' to 'int *'
  (long*)                 TU; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnknown *' to 'long *'
  (float*)                TU; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnknown *' to 'float *'
  (double*)               TU; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnknown *' to 'double *'
  (PublicDerived*)        TU; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnknown *' to 'PublicDerived *'
  (ProtectedDerived*)     TU; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnknown *' to 'ProtectedDerived *'
  (PrivateDerived*)       TU; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnknown *' to 'PrivateDerived *'
  (PublicDerived2*)       TU; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnknown *' to 'PublicDerived2 *'
  (PublicDerived3*)       TU; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnknown *' to 'PublicDerived3 *'

  (volatile char**)       UU; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingUnknown *' to 'volatile char **'
  (const char**)          UU; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingUnknown *' to 'const char **'
  (const volatile char**) UU; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingUnknown *' to 'const volatile char **'
  (short*)                UU; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingUnknown *' to 'short *'
  (int*)                  UU; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingUnknown *' to 'int *'
  (long*)                 UU; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingUnknown *' to 'long *'
  (float*)                UU; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingUnknown *' to 'float *'
  (double*)               UU; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingUnknown *' to 'double *'
  (PublicDerived*)        UU; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingUnknown *' to 'PublicDerived *'
  (ProtectedDerived*)     UU; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingUnknown *' to 'ProtectedDerived *'
  (PrivateDerived*)       UU; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingUnknown *' to 'PrivateDerived *'
  (PublicDerived2*)       UU; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingUnknown *' to 'PublicDerived2 *'
  (PublicDerived3*)       UU; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingUnknown *' to 'PublicDerived3 *'

  reinterpret_cast<volatile char**>      (U); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Unknown *' to 'volatile char **'
  reinterpret_cast<const char**>         (U); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Unknown *' to 'const char **'
  reinterpret_cast<const volatile char**>(U); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Unknown *' to 'const volatile char **'
  reinterpret_cast<short*>               (U); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Unknown *' to 'short *'
  reinterpret_cast<int*>                 (U); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Unknown *' to 'int *'
  reinterpret_cast<long*>                (U); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Unknown *' to 'long *'
  reinterpret_cast<float*>               (U); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Unknown *' to 'float *'
  reinterpret_cast<double*>              (U); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Unknown *' to 'double *'
  reinterpret_cast<PublicDerived*>       (U); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Unknown *' to 'PublicDerived *'
  reinterpret_cast<ProtectedDerived*>    (U); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Unknown *' to 'ProtectedDerived *'
  reinterpret_cast<PrivateDerived*>      (U); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Unknown *' to 'PrivateDerived *'
  reinterpret_cast<PublicDerived2*>      (U); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Unknown *' to 'PublicDerived2 *'
  reinterpret_cast<PublicDerived3*>      (U); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union Unknown *' to 'PublicDerived3 *'

  reinterpret_cast<volatile char**>      (TU); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnknown *' to 'volatile char **'
  reinterpret_cast<const char**>         (TU); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnknown *' to 'const char **'
  reinterpret_cast<const volatile char**>(TU); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnknown *' to 'const volatile char **'
  reinterpret_cast<short*>               (TU); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnknown *' to 'short *'
  reinterpret_cast<int*>                 (TU); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnknown *' to 'int *'
  reinterpret_cast<long*>                (TU); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnknown *' to 'long *'
  reinterpret_cast<float*>               (TU); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnknown *' to 'float *'
  reinterpret_cast<double*>              (TU); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnknown *' to 'double *'
  reinterpret_cast<PublicDerived*>       (TU); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnknown *' to 'PublicDerived *'
  reinterpret_cast<ProtectedDerived*>    (TU); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnknown *' to 'ProtectedDerived *'
  reinterpret_cast<PrivateDerived*>      (TU); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnknown *' to 'PrivateDerived *'
  reinterpret_cast<PublicDerived2*>      (TU); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnknown *' to 'PublicDerived2 *'
  reinterpret_cast<PublicDerived3*>      (TU); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefUnknown *' to 'PublicDerived3 *'

  reinterpret_cast<volatile char**>      (UU); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingUnknown *' to 'volatile char **'
  reinterpret_cast<const char**>         (UU); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingUnknown *' to 'const char **'
  reinterpret_cast<const volatile char**>(UU); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingUnknown *' to 'const volatile char **'
  reinterpret_cast<short*>               (UU); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingUnknown *' to 'short *'
  reinterpret_cast<int*>                 (UU); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingUnknown *' to 'int *'
  reinterpret_cast<long*>                (UU); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingUnknown *' to 'long *'
  reinterpret_cast<float*>               (UU); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingUnknown *' to 'float *'
  reinterpret_cast<double*>              (UU); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingUnknown *' to 'double *'
  reinterpret_cast<PublicDerived*>       (UU); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingUnknown *' to 'PublicDerived *'
  reinterpret_cast<ProtectedDerived*>    (UU); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingUnknown *' to 'ProtectedDerived *'
  reinterpret_cast<PrivateDerived*>      (UU); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingUnknown *' to 'PrivateDerived *'
  reinterpret_cast<PublicDerived2*>      (UU); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingUnknown *' to 'PublicDerived2 *'
  reinterpret_cast<PublicDerived3*>      (UU); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingUnknown *' to 'PublicDerived3 *'
}
