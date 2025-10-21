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

class Base { int I; };
class PublicDerived : public Base { };
class ProtectedDerived : protected Base { };
class PrivateDerived : private Base { };
class PublicDerived2 : public PublicDerived { };
class PublicDerived3 : public PublicDerived2 { };

union MyUnion {
  volatile char *F1;
  const char *F2;
  const volatile char *F3;
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
};

typedef union MyUnion TypedefMyUnion;
using UsingMyUnion = union MyUnion;

// static_cast and dynamic_cast expressions would produce compile-time errors
// in C++, if used for this purpose, so they are not present.

// Implicit casts like char *c = &MyUnion are also compile-time errors in C++.
// Those cases are included in the C test file.

void castToTypeInUnion(union MyUnion *U, TypedefMyUnion *TU, UsingMyUnion *UU) {
  (volatile char**) U;
  (const char**) U;
  (const volatile char**) U;
  (short*) U;
  (float*) U;
  (ShortPtrTypedef*) U;
  (ShortPtrTypedefPtr) U;
  (ShortPtrUsing*) U;
  (PublicDerived*) U;
  (ProtectedDerived*) U;
  (PrivateDerived*) U;
  (PublicDerived2*) U;
  (PublicDerived3*) U;
  (ShortPtrTypedef) U;
  (ShortPtrTypedefTypedef) U;
  (ShortPtrUsing) U;
  (ShortPtrUsingUsing) U;

  (volatile char**) TU;
  (const char**) TU;
  (const volatile char**) TU;
  (short*) TU;
  (float*) TU;
  (ShortPtrTypedef*) TU;
  (ShortPtrTypedefPtr) TU;
  (ShortPtrUsing*) TU;
  (PublicDerived*) TU;
  (ProtectedDerived*) TU;
  (PrivateDerived*) TU;
  (PublicDerived2*) TU;
  (PublicDerived3*) TU;
  (ShortPtrTypedef) TU;
  (ShortPtrTypedefTypedef) TU;
  (ShortPtrUsing) TU;
  (ShortPtrUsingUsing) TU;

  (volatile char**) UU;
  (const char**) UU;
  (const volatile char**) UU;
  (short*) UU;
  (float*) UU;
  (ShortPtrTypedef*) UU;
  (ShortPtrTypedefPtr) UU;
  (ShortPtrUsing*) UU;
  (PublicDerived*) UU;
  (ProtectedDerived*) UU;
  (PrivateDerived*) UU;
  (PublicDerived2*) UU;
  (PublicDerived3*) UU;
  (ShortPtrTypedef) UU;
  (ShortPtrTypedefTypedef) UU;
  (ShortPtrUsing) UU;
  (ShortPtrUsingUsing) UU;

  reinterpret_cast<volatile char**>(U);
  reinterpret_cast<const char**>(U);
  reinterpret_cast<const volatile char**>(U);
  reinterpret_cast<short*>(U);
  reinterpret_cast<float*>(U);
  reinterpret_cast<ShortPtrTypedef*>(U);
  reinterpret_cast<ShortPtrTypedefPtr>(U);
  reinterpret_cast<ShortPtrUsing*>(U);
  reinterpret_cast<PublicDerived*>(U);
  reinterpret_cast<ProtectedDerived*>(U);
  reinterpret_cast<PrivateDerived*>(U);
  reinterpret_cast<PublicDerived2*>(U);
  reinterpret_cast<PublicDerived3*>(U);
  reinterpret_cast<ShortPtrTypedef>(U);
  reinterpret_cast<ShortPtrTypedefTypedef>(U);
  reinterpret_cast<ShortPtrUsing>(U);
  reinterpret_cast<ShortPtrUsingUsing>(U);

  reinterpret_cast<volatile char**>(TU);
  reinterpret_cast<const char**>(TU);
  reinterpret_cast<const volatile char**>(TU);
  reinterpret_cast<short*>(TU);
  reinterpret_cast<float*>(TU);
  reinterpret_cast<ShortPtrTypedef*>(TU);
  reinterpret_cast<ShortPtrTypedefPtr>(TU);
  reinterpret_cast<ShortPtrUsing*>(TU);
  reinterpret_cast<PublicDerived*>(TU);
  reinterpret_cast<ProtectedDerived*>(TU);
  reinterpret_cast<PrivateDerived*>(TU);
  reinterpret_cast<PublicDerived2*>(TU);
  reinterpret_cast<PublicDerived3*>(TU);
  reinterpret_cast<ShortPtrTypedef>(TU);
  reinterpret_cast<ShortPtrTypedefTypedef>(TU);
  reinterpret_cast<ShortPtrUsing>(TU);
  reinterpret_cast<ShortPtrUsingUsing>(TU);

  reinterpret_cast<volatile char**>(UU);
  reinterpret_cast<const char**>(UU);
  reinterpret_cast<const volatile char**>(UU);
  reinterpret_cast<short*>(UU);
  reinterpret_cast<float*>(UU);
  reinterpret_cast<ShortPtrTypedef*>(UU);
  reinterpret_cast<ShortPtrTypedefPtr>(UU);
  reinterpret_cast<ShortPtrUsing*>(UU);
  reinterpret_cast<PublicDerived*>(UU);
  reinterpret_cast<ProtectedDerived*>(UU);
  reinterpret_cast<PrivateDerived*>(UU);
  reinterpret_cast<PublicDerived2*>(UU);
  reinterpret_cast<PublicDerived3*>(UU);
  reinterpret_cast<ShortPtrTypedef>(UU);
  reinterpret_cast<ShortPtrTypedefTypedef>(UU);
  reinterpret_cast<ShortPtrUsing>(UU);
  reinterpret_cast<ShortPtrUsingUsing>(UU);
}

void castToBaseClassPointerTest() {
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
}

#include "stdnamespace.h"
#include <pthread.h>

void optionDependentDefaultBehaviors(union MyUnion *U, TypedefMyUnion *TU, UsingMyUnion *UU) {
  /* AllowCastToCharPtr */
  // Implicit casts to char* cause compile errors
  (char*) U;
  (char*) TU;
  (char*) UU;
  reinterpret_cast<char*>(U);
  reinterpret_cast<char*>(TU);
  reinterpret_cast<char*>(UU);

  /* AllowCastToVoidPtr */
  void *V;
  V = U;
  V = TU;
  V = UU;
  (void*) U;
  (void*) TU;
  (void*) UU;
  reinterpret_cast<void*>(U);
  reinterpret_cast<void*>(TU);
  reinterpret_cast<void*>(UU);

  /* AllowCastToSubField */
  struct Foo *SubFieldPtr1;
  (struct Foo*) U;
  (struct Foo*) TU;
  (struct Foo*) UU;
  reinterpret_cast<struct Foo*>(U);
  reinterpret_cast<struct Foo*>(TU);
  reinterpret_cast<struct Foo*>(UU);

  double ***SubFieldPtr2;
  (double***) U;
  (double***) TU;
  (double***) UU;
  reinterpret_cast<double***>(U);
  reinterpret_cast<double***>(TU);
  reinterpret_cast<double***>(UU);

  struct Bar *SubFieldPtr3;
  (struct Bar*) U;
  (struct Bar*) TU;
  (struct Bar*) UU;
  reinterpret_cast<struct Bar*>(U);
  reinterpret_cast<struct Bar*>(TU);
  reinterpret_cast<struct Bar*>(UU);

  void ***SubFieldPtr4;
  (void ***) U;      // CHECK-MESSAGES: :[[@LINE]]:14: warning: the union pointed to by this expression has no field with the type 'void **'
  (void ***) TU;     // CHECK-MESSAGES: :[[@LINE]]:14: warning: the union pointed to by this expression has no field with the type 'void **'
  (void ***) UU;     // CHECK-MESSAGES: :[[@LINE]]:14: warning: the union pointed to by this expression has no field with the type 'void **'
  reinterpret_cast<void ***>(U);  // CHECK-MESSAGES: :[[@LINE]]:30: warning: the union pointed to by this expression has no field with the type 'void **'
  reinterpret_cast<void ***>(TU); // CHECK-MESSAGES: :[[@LINE]]:30: warning: the union pointed to by this expression has no field with the type 'void **'
  reinterpret_cast<void ***>(UU); // CHECK-MESSAGES: :[[@LINE]]:30: warning: the union pointed to by this expression has no field with the type 'void **'

  void **SubFieldPtr5;
  (void **) U;
  (void **) TU;
  (void **) UU;
  reinterpret_cast<void **>(U);
  reinterpret_cast<void **>(TU);
  reinterpret_cast<void **>(UU);

  /* IgnoreIfUnionIsFromStdNamespace */
  std::pthread_mutex_t *T1;
  (double*) T1;
  reinterpret_cast<double*>(T1);

  /* IgnoreIfUnionIsFromSystemHeader */
  pthread_mutex_t *T2;
  (double*) T2;
  reinterpret_cast<double*>(T2);
}

void irrelevantCastExpressions(union MyUnion *U, TypedefMyUnion *TU, UsingMyUnion *UU) {
  long LI;
  unsigned long UL = LI;
  (unsigned long) LI;
  // This is already a compile time error.
  // reinterpret_cast<unsigned long>(LI);

  // It does not matter that the union has a field with the same type
  // as the aliased type. Typedefs and usings are not considered "transparent"
  // in that sense by the check.
  (void*) LI;
  reinterpret_cast<void*>(LI);

  // Should not get analyzed, because D does not point to a union.
  // Also 0 instead of nullptr, because the latter exists only from C++11.
  Base *B = 0;
  PublicDerived *D = 0;
  B = D;
  B = (Base*) D;
  B = reinterpret_cast<Base*>(D);
  B = static_cast<Base*>(D);

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

void castsToTypeWithNoCorresspondingFieldInUnion(union MyUnion *U, TypedefMyUnion *TU, UsingMyUnion *UU) {
  (long*) U; // CHECK-MESSAGES: :[[@LINE]]:11: warning: the union pointed to by this expression has no field with the type 'long'
  (long*) TU; // CHECK-MESSAGES: :[[@LINE]]:11: warning: the union pointed to by this expression has no field with the type 'long'
  (long*) UU; // CHECK-MESSAGES: :[[@LINE]]:11: warning: the union pointed to by this expression has no field with the type 'long'

  (LongPtrTypedef) U; // CHECK-MESSAGES: :[[@LINE]]:20: warning: the union pointed to by this expression has no field with the type 'long'
  (LongPtrTypedef) TU; // CHECK-MESSAGES: :[[@LINE]]:20: warning: the union pointed to by this expression has no field with the type 'long'
  (LongPtrTypedef) UU; // CHECK-MESSAGES: :[[@LINE]]:20: warning: the union pointed to by this expression has no field with the type 'long'

  (LongPtrUsing) U; // CHECK-MESSAGES: :[[@LINE]]:18: warning: the union pointed to by this expression has no field with the type 'long'
  (LongPtrUsing) TU; // CHECK-MESSAGES: :[[@LINE]]:18: warning: the union pointed to by this expression has no field with the type 'long'
  (LongPtrUsing) UU; // CHECK-MESSAGES: :[[@LINE]]:18: warning: the union pointed to by this expression has no field with the type 'long'

  reinterpret_cast<long*>(U); // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'long'
  reinterpret_cast<long*>(TU); // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'long'
  reinterpret_cast<long*>(UU); // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'long'

  reinterpret_cast<LongPtrTypedef>(U); // CHECK-MESSAGES: :[[@LINE]]:36: warning: the union pointed to by this expression has no field with the type 'long'
  reinterpret_cast<LongPtrTypedef>(TU); // CHECK-MESSAGES: :[[@LINE]]:36: warning: the union pointed to by this expression has no field with the type 'long'
  reinterpret_cast<LongPtrTypedef>(UU); // CHECK-MESSAGES: :[[@LINE]]:36: warning: the union pointed to by this expression has no field with the type 'long'

  reinterpret_cast<LongPtrUsing>(U); // CHECK-MESSAGES: :[[@LINE]]:34: warning: the union pointed to by this expression has no field with the type 'long'
  reinterpret_cast<LongPtrUsing>(TU); // CHECK-MESSAGES: :[[@LINE]]:34: warning: the union pointed to by this expression has no field with the type 'long'
  reinterpret_cast<LongPtrUsing>(UU); // CHECK-MESSAGES: :[[@LINE]]:34: warning: the union pointed to by this expression has no field with the type 'long'
}

void castsWithQualifierMismatches() {
  typedef union { char *Ptr; } TypedefU1;
  using UsingU1 = union { char *Ptr; };
  TypedefU1 *TU1;
  UsingU1 *UU1;
  union { char *Ptr; } *U1;
  (volatile char**)       U1; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'volatile char *'
  (const char**)          U1; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'const char *'
  (const volatile char**) U1; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'const volatile char *'
  reinterpret_cast<volatile char**>      (U1); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'volatile char *'
  reinterpret_cast<const char**>         (U1); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'const char *'
  reinterpret_cast<const volatile char**>(U1); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'const volatile char *'

  (volatile char**)       TU1; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'volatile char *'
  (const char**)          TU1; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'const char *'
  (const volatile char**) TU1; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'const volatile char *'
  reinterpret_cast<volatile char**>      (TU1); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'volatile char *'
  reinterpret_cast<const char**>         (TU1); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'const char *'
  reinterpret_cast<const volatile char**>(TU1); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'const volatile char *'

  (volatile char**)       UU1; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'volatile char *'
  (const char**)          UU1; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'const char *'
  (const volatile char**) UU1; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'const volatile char *'
  reinterpret_cast<volatile char**>      (UU1); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'volatile char *'
  reinterpret_cast<const char**>         (UU1); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'const char *'
  reinterpret_cast<const volatile char**>(UU1); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'const volatile char *'


  typedef union { const char *Ptr; } TypedefU2;
  using UsingU2 = union { const char *Ptr; };
  TypedefU2 *TU2;
  UsingU2 *UU2;
  union { const char *Ptr; } *U2;
  (char**)                U2; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'char *'
  (volatile char**)       U2; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'volatile char *'
  (const volatile char**) U2; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'const volatile char *'
  reinterpret_cast<char**>               (U2); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'char *'
  reinterpret_cast<volatile char**>      (U2); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'volatile char *'
  reinterpret_cast<const volatile char**>(U2); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'const volatile char *'

  (char**)                TU2; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'char *'
  (volatile char**)       TU2; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'volatile char *'
  (const volatile char**) TU2; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'const volatile char *'
  reinterpret_cast<char**>               (TU2); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'char *'
  reinterpret_cast<volatile char**>      (TU2); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'volatile char *'
  reinterpret_cast<const volatile char**>(TU2); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'const volatile char *'

  (char**)                UU2; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'char *'
  (volatile char**)       UU2; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'volatile char *'
  (const volatile char**) UU2; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'const volatile char *'
  reinterpret_cast<char**>               (UU2); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'char *'
  reinterpret_cast<volatile char**>      (UU2); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'volatile char *'
  reinterpret_cast<const volatile char**>(UU2); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'const volatile char *'


  typedef union { volatile char *Ptr; } TypedefU3;
  using UsingU3 = union { volatile char *Ptr; };
  TypedefU3 *TU3;
  UsingU3 *UU3;
  union { volatile char *Ptr; } *U3;
  (char**)                U3; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'char *'
  (const char**)          U3; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'const char *'
  (const volatile char**) U3; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'const volatile char *'
  reinterpret_cast<char**>               (U3); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'char *'
  reinterpret_cast<const char**>         (U3); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'const char *'
  reinterpret_cast<const volatile char**>(U3); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'const volatile char *'

  (char**)                TU3; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'char *'
  (const char**)          TU3; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'const char *'
  (const volatile char**) TU3; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'const volatile char *'
  reinterpret_cast<char**>               (TU3); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'char *'
  reinterpret_cast<const char**>         (TU3); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'const char *'
  reinterpret_cast<const volatile char**>(TU3); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'const volatile char *'

  (char**)                UU3; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'char *'
  (const char**)          UU3; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'const char *'
  (const volatile char**) UU3; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'const volatile char *'
  reinterpret_cast<char**>               (UU3); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'char *'
  reinterpret_cast<const char**>         (UU3); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'const char *'
  reinterpret_cast<const volatile char**>(UU3); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'const volatile char *'

  typedef union { const volatile char *Ptr; } TypedefU4;
  using UsingU4 = union { const volatile char *Ptr; };
  TypedefU4 *TU4;
  UsingU4 *UU4;
  union { const volatile char *Ptr; } *U4;
  (char**)                U4; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'char *'
  (volatile char**)       U4; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'volatile char *'
  (const char**)          U4; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'const char *'
  reinterpret_cast<char**>               (U4); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'char *'
  reinterpret_cast<volatile char**>      (U4); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'volatile char *'
  reinterpret_cast<const char**>         (U4); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'const char *'

  (char**)                TU4; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'char *'
  (volatile char**)       TU4; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'volatile char *'
  (const char**)          TU4; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'const char *'
  reinterpret_cast<char**>               (TU4); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'char *'
  reinterpret_cast<volatile char**>      (TU4); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'volatile char *'
  reinterpret_cast<const char**>         (TU4); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'const char *'

  (char**)                UU4; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'char *'
  (volatile char**)       UU4; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'volatile char *'
  (const char**)          UU4; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'const char *'
  reinterpret_cast<char**>               (UU4); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'char *'
  reinterpret_cast<volatile char**>      (UU4); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'volatile char *'
  reinterpret_cast<const char**>         (UU4); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'const char *'
}

typedef union Unknown TypedefUnknown;
using UsingUnknown = union Unknown;

void castsWhenUnionDefinitionIsUnknown(union Unknown *U, TypedefUnknown *TU, UsingUnknown *UU) {
  (volatile char**)       U; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'volatile char *'
  (const char**)          U; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'const char *'
  (const volatile char**) U; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'const volatile char *'
  (short*)                U; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'short'
  (int*)                  U; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'int'
  (long*)                 U; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'long'
  (float*)                U; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'float'
  (double*)               U; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'double'
  (PublicDerived*)        U; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'PublicDerived'
  (ProtectedDerived*)     U; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'ProtectedDerived'
  (PrivateDerived*)       U; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'PrivateDerived'
  (PublicDerived2*)       U; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'PublicDerived2'
  (PublicDerived3*)       U; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'PublicDerived3'

  (volatile char**)       TU; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'volatile char *'
  (const char**)          TU; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'const char *'
  (const volatile char**) TU; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'const volatile char *'
  (short*)                TU; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'short'
  (int*)                  TU; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'int'
  (long*)                 TU; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'long'
  (float*)                TU; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'float'
  (double*)               TU; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'double'
  (PublicDerived*)        TU; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'PublicDerived'
  (ProtectedDerived*)     TU; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'ProtectedDerived'
  (PrivateDerived*)       TU; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'PrivateDerived'
  (PublicDerived2*)       TU; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'PublicDerived2'
  (PublicDerived3*)       TU; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'PublicDerived3'

  (volatile char**)       UU; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'volatile char *'
  (const char**)          UU; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'const char *'
  (const volatile char**) UU; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'const volatile char *'
  (short*)                UU; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'short'
  (int*)                  UU; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'int'
  (long*)                 UU; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'long'
  (float*)                UU; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'float'
  (double*)               UU; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'double'
  (PublicDerived*)        UU; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'PublicDerived'
  (ProtectedDerived*)     UU; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'ProtectedDerived'
  (PrivateDerived*)       UU; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'PrivateDerived'
  (PublicDerived2*)       UU; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'PublicDerived2'
  (PublicDerived3*)       UU; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'PublicDerived3'

  reinterpret_cast<volatile char**>      (U); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'volatile char *'
  reinterpret_cast<const char**>         (U); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'const char *'
  reinterpret_cast<const volatile char**>(U); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'const volatile char *'
  reinterpret_cast<short*>               (U); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'short'
  reinterpret_cast<int*>                 (U); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'int'
  reinterpret_cast<long*>                (U); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'long'
  reinterpret_cast<float*>               (U); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'float'
  reinterpret_cast<double*>              (U); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'double'
  reinterpret_cast<PublicDerived*>       (U); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'PublicDerived'
  reinterpret_cast<ProtectedDerived*>    (U); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'ProtectedDerived'
  reinterpret_cast<PrivateDerived*>      (U); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'PrivateDerived'
  reinterpret_cast<PublicDerived2*>      (U); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'PublicDerived2'
  reinterpret_cast<PublicDerived3*>      (U); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'PublicDerived3'

  reinterpret_cast<volatile char**>      (TU); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'volatile char *'
  reinterpret_cast<const char**>         (TU); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'const char *'
  reinterpret_cast<const volatile char**>(TU); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'const volatile char *'
  reinterpret_cast<short*>               (TU); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'short'
  reinterpret_cast<int*>                 (TU); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'int'
  reinterpret_cast<long*>                (TU); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'long'
  reinterpret_cast<float*>               (TU); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'float'
  reinterpret_cast<double*>              (TU); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'double'
  reinterpret_cast<PublicDerived*>       (TU); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'PublicDerived'
  reinterpret_cast<ProtectedDerived*>    (TU); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'ProtectedDerived'
  reinterpret_cast<PrivateDerived*>      (TU); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'PrivateDerived'
  reinterpret_cast<PublicDerived2*>      (TU); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'PublicDerived2'
  reinterpret_cast<PublicDerived3*>      (TU); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'PublicDerived3'

  reinterpret_cast<volatile char**>      (UU); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'volatile char *'
  reinterpret_cast<const char**>         (UU); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'const char *'
  reinterpret_cast<const volatile char**>(UU); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'const volatile char *'
  reinterpret_cast<short*>               (UU); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'short'
  reinterpret_cast<int*>                 (UU); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'int'
  reinterpret_cast<long*>                (UU); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'long'
  reinterpret_cast<float*>               (UU); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'float'
  reinterpret_cast<double*>              (UU); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'double'
  reinterpret_cast<PublicDerived*>       (UU); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'PublicDerived'
  reinterpret_cast<ProtectedDerived*>    (UU); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'ProtectedDerived'
  reinterpret_cast<PrivateDerived*>      (UU); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'PrivateDerived'
  reinterpret_cast<PublicDerived2*>      (UU); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'PublicDerived2'
  reinterpret_cast<PublicDerived3*>      (UU); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'PublicDerived3'
}
