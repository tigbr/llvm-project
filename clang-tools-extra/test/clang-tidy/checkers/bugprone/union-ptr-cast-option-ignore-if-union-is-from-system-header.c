// RUN: %check_clang_tidy %s bugprone-union-ptr-cast %t \
// RUN:   --config='{CheckOptions: { \
// RUN:     bugprone-union-ptr-cast.AlwaysAllowCastToVoidPtr: false, \
// RUN:     bugprone-union-ptr-cast.IgnoreIfUnionIsFromSystemHeader: false \
// RUN:  }}' -- \
// RUN: -isystem %S/Inputs/union-ptr-cast/system

#include <pthread.h>

void fromSystemHeaderFile(pthread_mutex_t *T) {
  void *P = T; // CHECK-MESSAGES: :[[@LINE]]:13: warning: invalid cast from 'pthread_mutex_t *' to 'void *'
  (void*) T; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'pthread_mutex_t *' to 'void *'
}
