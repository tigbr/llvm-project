// RUN: %check_clang_tidy -std=c++98-or-later %s bugprone-union-ptr-cast %t \
// RUN:   --config='{CheckOptions: { \
// RUN:     bugprone-union-ptr-cast.CompareCanonicalTypes: false \
// RUN:  }}' --

typedef short *ShortPtrTypedef;
typedef ShortPtrTypedef ShortPtrTypedefTypedef;
typedef ShortPtrTypedef *ShortPtrTypedefPtr;

struct BarStruct { int i; };
class BarClass { int i; };
union BarUnion { int i; };
enum BarEnum { BarEnumVal };

union MyUnion {
  short F1;
  struct BarStruct F2;
  union BarUnion F3;
  enum BarEnum F4;
  class BarClass F5;
};
typedef union MyUnion TypedefMyUnion;
using UsingMyUnion = union MyUnion;

void test(union MyUnion *U, TypedefMyUnion *TU, UsingMyUnion *UU) {

  // Do not differentiate these types when CompareCanonicalTypes is disabled
  (struct BarStruct*) U;
  (class BarClass*) U;
  (union BarUnion*) U;
  (enum BarEnum*) U;
  (BarStruct*) U;
  (BarClass*) U;
  (BarUnion*) U;
  (BarEnum*) U;

  (struct BarStruct*) TU;
  (class BarClass*) TU;
  (union BarUnion*) TU;
  (enum BarEnum*) TU;
  (BarStruct*) TU;
  (BarClass*) TU;
  (BarUnion*) TU;
  (BarEnum*) TU;

  (struct BarStruct*) UU;
  (class BarClass*) UU;
  (union BarUnion*) UU;
  (enum BarEnum*) UU;
  (BarStruct*) UU;
  (BarClass*) UU;
  (BarUnion*) UU;
  (BarEnum*) UU;

  (ShortPtrTypedef)        U;
  (ShortPtrTypedef*)       U; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union MyUnion *' to 'ShortPtrTypedef *'
  (ShortPtrTypedefTypedef) U;
  (ShortPtrTypedefPtr)     U; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union MyUnion *' to 'ShortPtrTypedef *'

  (ShortPtrTypedef)        TU;
  (ShortPtrTypedef*)       TU; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefMyUnion *' to 'ShortPtrTypedef *'
  (ShortPtrTypedefTypedef) TU;
  (ShortPtrTypedefPtr)     TU; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefMyUnion *' to 'ShortPtrTypedef *'

  (ShortPtrTypedef)        UU;
  (ShortPtrTypedef*)       UU; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingMyUnion *' to 'ShortPtrTypedef *'
  (ShortPtrTypedefTypedef) UU;
  (ShortPtrTypedefPtr)     UU; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingMyUnion *' to 'ShortPtrTypedef *'

  reinterpret_cast<ShortPtrTypedef>(U);
  reinterpret_cast<ShortPtrTypedef*>(U); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union MyUnion *' to 'ShortPtrTypedef *'
  reinterpret_cast<ShortPtrTypedefTypedef>(U);
  reinterpret_cast<ShortPtrTypedefPtr>(U); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union MyUnion *' to 'ShortPtrTypedef *'

  reinterpret_cast<ShortPtrTypedef>(TU);
  reinterpret_cast<ShortPtrTypedef*>(TU); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefMyUnion *' to 'ShortPtrTypedef *'
  reinterpret_cast<ShortPtrTypedefTypedef>(TU);
  reinterpret_cast<ShortPtrTypedefPtr>(TU); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefMyUnion *' to 'ShortPtrTypedef *'

  reinterpret_cast<ShortPtrTypedef>(UU);
  reinterpret_cast<ShortPtrTypedef*>(UU); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingMyUnion *' to 'ShortPtrTypedef *'
  reinterpret_cast<ShortPtrTypedefTypedef>(UU);
  reinterpret_cast<ShortPtrTypedefPtr>(UU); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'UsingMyUnion *' to 'ShortPtrTypedef *'

}
