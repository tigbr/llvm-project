// RUN: %check_clang_tidy -std=c++98-or-later %s bugprone-union-ptr-cast %t -- -- \
// RUN: -I%S/Inputs/union-ptr-cast \
// RUN: -isystem %S/Inputs/union-ptr-cast/system

typedef short *short_ptr_typedef;
using short_ptr_using = short*;

class Base { int I; };
class PublicDerived : public Base { };
class ProtectedDerived : protected Base { };
class PrivateDerived : private Base { };
class PublicDerived2 : public PublicDerived { };
class PublicDerived3 : public PublicDerived2 { };

union MyUnion {
  volatile char *vptr;
  const char *cptr;
  const volatile char *vcptr;
  short s;
  float f;
  short_ptr_typedef spt;
  short_ptr_using spu;
  PublicDerived pub;
  ProtectedDerived prot;
  PrivateDerived priv;
  PublicDerived2 pub2;
  PublicDerived3 pub3;
};

// static_cast and dynamic_cast expressions would produce compile-time errors
// in C++, if used for this purpose, so they are not present.

// Implicit casts like char *c = &MyUnion are also compile-time errors in C++.
// Those cases are included only in the C test file.

void castToTypeInUnion(union MyUnion *U) {
  (volatile char**) U;
  (const char**) U;
  (const volatile char**) U;
  (short*) U;
  (float*) U;
  (short_ptr_typedef*) U;
  (short_ptr_using*) U;
  (PublicDerived*) U;
  (ProtectedDerived*) U;
  (PrivateDerived*) U;
  (PublicDerived2*) U;
  (PublicDerived3*) U;

  reinterpret_cast<volatile char**>(U);
  reinterpret_cast<const char**>(U);
  reinterpret_cast<const volatile char**>(U);
  reinterpret_cast<short*>(U);
  reinterpret_cast<float*>(U);
  reinterpret_cast<short_ptr_typedef*>(U);
  reinterpret_cast<short_ptr_using*>(U);
  reinterpret_cast<PublicDerived*>(U);
  reinterpret_cast<ProtectedDerived*>(U);
  reinterpret_cast<PrivateDerived*>(U);
  reinterpret_cast<PublicDerived2*>(U);
  reinterpret_cast<PublicDerived3*>(U);
}

void castToBaseClassPointerTest() {
  union { PublicDerived  field; }   *U1;
  (Base*) U1;
  reinterpret_cast<Base*>(U1);

  union { PublicDerived2 field; }   *U2;
  (Base*) U2;
  reinterpret_cast<Base*>(U2);

  union { PublicDerived3 field; }   *U3; 
  (Base*) U3;
  reinterpret_cast<Base*>(U3);

  union { ProtectedDerived field; } *U4; 
  (Base*) U4;
  reinterpret_cast<Base*>(U4);

  union { PrivateDerived field; }   *U5; 
  (Base*) U5;
  reinterpret_cast<Base*>(U5);
}

void castToUnionItself(union MyUnion *U) {
  union MyUnion *MU = U;
  (union MyUnion*) U;
  reinterpret_cast<union MyUnion*>(U);
}

//
// Test cases where a diag message is expected.
//

void optionDependentDefaultBehaviors(union MyUnion *U) {
  // This implicit cast does not give an error in C++ mode so it included here
  void *v = U;

  (char*) U;
  (void*) U;

  reinterpret_cast<char*>(U);
  reinterpret_cast<void*>(U);
}

//
// Test cases where a diag message is expected.
//

void castsToTypesWithNoCorresspondingFieldInUnion(union MyUnion *U) {
  (long*) U; // CHECK-MESSAGES: :[[@LINE]]:11: warning: the union pointed to by this expression has no field with the type 'long'

  reinterpret_cast<long*>            (U); // CHECK-MESSAGES: :[[@LINE]]:39: warning: the union pointed to by this expression has no field with the type 'long'
}

void castsWithQualifierMismatches() {
  union { char *Ptr; }   *U1;
  (volatile char**)       U1; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'volatile char *'
  (const char**)          U1; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'const char *'
  (const volatile char**) U1; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'const volatile char *'
  reinterpret_cast<volatile char**>      (U1); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'volatile char *'
  reinterpret_cast<const char**>         (U1); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'const char *'
  reinterpret_cast<const volatile char**>(U1); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'const volatile char *'

  union { const char *Ptr; } *U2;
  (char**)                U2; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'char *'
  (volatile char**)       U2; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'volatile char *'
  (const volatile char**) U2; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'const volatile char *'
  reinterpret_cast<char**>               (U2); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'char *'
  reinterpret_cast<volatile char**>      (U2); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'volatile char *'
  reinterpret_cast<const volatile char**>(U2); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'const volatile char *'

  union { volatile char *Ptr; } *U3;
  (char**)                U3; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'char *'
  (const char**)          U3; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'const char *'
  (const volatile char**) U3; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'const volatile char *'
  reinterpret_cast<char**>               (U3); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'char *'
  reinterpret_cast<const char**>         (U3); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'const char *'
  reinterpret_cast<const volatile char**>(U3); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'const volatile char *'

  union { const volatile char *Ptr; } *U4;
  (char**)                U4; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'char *'
  (volatile char**)       U4; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'volatile char *'
  (const char**)          U4; // CHECK-MESSAGES: :[[@LINE]]:27: warning: the union pointed to by this expression has no field with the type 'const char *'
  reinterpret_cast<char**>               (U4); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'char *'
  reinterpret_cast<volatile char**>      (U4); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'volatile char *'
  reinterpret_cast<const char**>         (U4); // CHECK-MESSAGES: :[[@LINE]]:43: warning: the union pointed to by this expression has no field with the type 'const char *'
}

void castsWhenUnionDefinitionIsUnknown(union Unknown *U) {
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
}

void irrelevantCastExpressions(union MyUnion *U) {
  long LI;
  unsigned long UL = LI;
  (unsigned long) LI;
  // Already an error at compile time
  // reinterpret_cast<unsigned long>(LI);

  // It does not matter that the union has a field with the same type
  // as the aliased type. Typedefs and usings are not considered "transparent"
  // in that sense.
  (short_ptr_typedef) U;
  (short_ptr_using) U;
  reinterpret_cast<short_ptr_typedef>(U);
  reinterpret_cast<short_ptr_using>  (U);

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
}

// Do not analyze those expression by default where the union pointed to
// comes from the std namespace or a system header file

#include "stdnamespace.h"
#include <pthread.h>

void fromStdNamespace(std::pthread_mutex_t *T) {
    void *P = T;
    (void*) T;
    reinterpret_cast<void*>(T);
}

void fromStdNamespace(pthread_mutex_t *T) {
    void *P = T;
    (void*) T;
    reinterpret_cast<void*>(T);
}
