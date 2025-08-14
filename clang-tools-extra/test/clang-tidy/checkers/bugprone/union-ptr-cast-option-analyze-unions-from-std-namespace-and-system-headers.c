// RUN: %check_clang_tidy %s bugprone-union-ptr-cast %t \
// RUN:   --config='{CheckOptions: { \
// RUN:     bugprone-union-ptr-cast.AlwaysAllowCastToVoidPtr: false, \
// RUN:     bugprone-union-ptr-cast.AnalyzeUnionsFromSystemHeaders: true \
// RUN:  }}' -- \
// RUN: -isystem %S/Inputs/union-ptr-cast/system

#include <pthread.h>

void fromSystemHeaderFile(pthread_mutex_t *T) {
  void *P = T; // CHECK-MESSAGES: :[[@LINE]]:13: warning: the union pointed to by this expression has no field with the type 'void'
  (void*) T; // CHECK-MESSAGES: :[[@LINE]]:11: warning: the union pointed to by this expression has no field with the type 'void'
}
