// RUN: %check_clang_tidy %s bugprone-union-ptr-cast %t \
// RUN:   --config='{CheckOptions: { \
// RUN:     bugprone-union-ptr-cast.CompareCanonicalTypes: false \
// RUN:  }}' --

typedef short *ShortPtrTypedef;
typedef ShortPtrTypedef ShortPtrTypedefTypedef;
typedef ShortPtrTypedef *ShortPtrTypedefPtr;

union MyUnion {
  short S;
};
typedef union MyUnion TypedefMyUnion;

void test(union MyUnion *U, TypedefMyUnion *TU) {
  ShortPtrTypedef t1;
  ShortPtrTypedef *t2;
  ShortPtrTypedefTypedef t3;
  ShortPtrTypedefPtr t4;
  t1 = U;
  t2 = U; // CHECK-MESSAGES: :[[@LINE]]:8: warning: invalid cast from 'union MyUnion *' to 'ShortPtrTypedef *'
  t3 = U;
  t4 = U; // CHECK-MESSAGES: :[[@LINE]]:8: warning: invalid cast from 'union MyUnion *' to 'ShortPtrTypedef *'

  t1 = TU;
  t2 = TU; // CHECK-MESSAGES: :[[@LINE]]:8: warning: invalid cast from 'TypedefMyUnion *' to 'ShortPtrTypedef *'
  t3 = TU;
  t4 = TU; // CHECK-MESSAGES: :[[@LINE]]:8: warning: invalid cast from 'TypedefMyUnion *' to 'ShortPtrTypedef *'

  (ShortPtrTypedef)        U;
  (ShortPtrTypedef*)       U; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union MyUnion *' to 'ShortPtrTypedef *'
  (ShortPtrTypedefTypedef) U;
  (ShortPtrTypedefPtr)     U; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'union MyUnion *' to 'ShortPtrTypedef *'

  (ShortPtrTypedef)        TU;
  (ShortPtrTypedef*)       TU; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefMyUnion *' to 'ShortPtrTypedef *'
  (ShortPtrTypedefTypedef) TU;
  (ShortPtrTypedefPtr)     TU; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'TypedefMyUnion *' to 'ShortPtrTypedef *'
}
