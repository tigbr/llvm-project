// RUN: %check_clang_tidy -std=c++98-or-later %s bugprone-union-ptr-cast %t \
// RUN:   --config='{CheckOptions: { \
// RUN:     bugprone-union-ptr-cast.CompareCanonicalTypes: true \
// RUN:  }}' --

typedef short Short;
typedef short *ShortPtr;

union MyUnion {
  Short a;
};

void test(union MyUnion *U) {
  (int*) U; // CHECK-MESSAGES: :[[@LINE]]:10: warning: the union pointed to by this expression has no field with the type 'int'
  (ShortPtr) U;
}
