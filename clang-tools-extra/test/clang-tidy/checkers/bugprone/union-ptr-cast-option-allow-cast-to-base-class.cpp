// RUN: %check_clang_tidy -std=c++98-or-later %s bugprone-union-ptr-cast %t -- \
// RUN:   --config='{CheckOptions: { \
// RUN:     bugprone-union-ptr-cast.AllowCastToBaseClass: false \
// RUN:  }}' --

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

typedef union MyUnion TypedefMyUnion;
using UsingMyUnion = union MyUnion;

void castToBaseClassPointerTest() {
  union { PublicDerived  field; } *U1;
  typedef union { PublicDerived  field; } TypedefU1;
  TypedefU1 *TU1;
  using UsingU1 = union { PublicDerived  field; };
  UsingU1 *UU1;
  (Base*) U1;                   // CHECK-MESSAGES: :[[@LINE]]:11: warning: the union pointed to by this expression has no field with the type 'Base'
  (Base*) TU1;                  // CHECK-MESSAGES: :[[@LINE]]:11: warning: the union pointed to by this expression has no field with the type 'Base'
  (Base*) UU1;                  // CHECK-MESSAGES: :[[@LINE]]:11: warning: the union pointed to by this expression has no field with the type 'Base'
  reinterpret_cast<Base*>(U1);  // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'Base'
  reinterpret_cast<Base*>(TU1); // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'Base'
  reinterpret_cast<Base*>(UU1); // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'Base'

#if 1
  union { PublicDerived2 field; } *U2;
  typedef union { PublicDerived2 field; } TypedefU2;
  TypedefU2 *TU2;
  using UsingU2 = union { PublicDerived2 field; };
  UsingU2 *UU2;
  (Base*) U2;                   // CHECK-MESSAGES: :[[@LINE]]:11: warning: the union pointed to by this expression has no field with the type 'Base'
  (Base*) TU2;                  // CHECK-MESSAGES: :[[@LINE]]:11: warning: the union pointed to by this expression has no field with the type 'Base'
  (Base*) UU2;                  // CHECK-MESSAGES: :[[@LINE]]:11: warning: the union pointed to by this expression has no field with the type 'Base'
  reinterpret_cast<Base*>(U2);  // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'Base'
  reinterpret_cast<Base*>(TU2); // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'Base'
  reinterpret_cast<Base*>(UU2); // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'Base'

  union { PublicDerived3 field; } *U3;
  typedef union { PublicDerived3 field; } TypedefU3;
  TypedefU3 *TU3;
  using UsingU3 = union { PublicDerived3 field; };
  UsingU3 *UU3;
  (Base*) U3;                   // CHECK-MESSAGES: :[[@LINE]]:11: warning: the union pointed to by this expression has no field with the type 'Base'
  (Base*) TU3;                  // CHECK-MESSAGES: :[[@LINE]]:11: warning: the union pointed to by this expression has no field with the type 'Base'
  (Base*) UU3;                  // CHECK-MESSAGES: :[[@LINE]]:11: warning: the union pointed to by this expression has no field with the type 'Base'
  reinterpret_cast<Base*>(U3);  // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'Base'
  reinterpret_cast<Base*>(TU3); // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'Base'
  reinterpret_cast<Base*>(UU3); // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'Base'

  union { ProtectedDerived field; } *U4;
  typedef union { PublicDerived3 field; } TypedefU4;
  TypedefU4 *TU4;
  using UsingU4 = union { PublicDerived3 field; };
  UsingU4 *UU4;
  (Base*) U4;                   // CHECK-MESSAGES: :[[@LINE]]:11: warning: the union pointed to by this expression has no field with the type 'Base'
  (Base*) TU4;                  // CHECK-MESSAGES: :[[@LINE]]:11: warning: the union pointed to by this expression has no field with the type 'Base'
  (Base*) UU4;                  // CHECK-MESSAGES: :[[@LINE]]:11: warning: the union pointed to by this expression has no field with the type 'Base'
  reinterpret_cast<Base*>(U4);  // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'Base'
  reinterpret_cast<Base*>(TU4); // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'Base'
  reinterpret_cast<Base*>(UU4); // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'Base'

  union { PrivateDerived field; } *U5;
  typedef union { PrivateDerived field; } TypedefU5;
  TypedefU5 *TU5;
  using UsingU5 = union { PrivateDerived field; };
  UsingU5 *UU5;
  (Base*) U5;                   // CHECK-MESSAGES: :[[@LINE]]:11: warning: the union pointed to by this expression has no field with the type 'Base'
  (Base*) TU5;                  // CHECK-MESSAGES: :[[@LINE]]:11: warning: the union pointed to by this expression has no field with the type 'Base'
  (Base*) UU5;                  // CHECK-MESSAGES: :[[@LINE]]:11: warning: the union pointed to by this expression has no field with the type 'Base'
  reinterpret_cast<Base*>(U5);  // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'Base'
  reinterpret_cast<Base*>(TU5); // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'Base'
  reinterpret_cast<Base*>(UU5); // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'Base'
#endif
}
