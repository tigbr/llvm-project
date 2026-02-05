// RUN: %check_clang_tidy %s bugprone-record-ptr-cast %t \
// RUN:   --config='{CheckOptions: { \
// RUN:     bugprone-record-ptr-cast.AlwaysAllowCastToVoidPtr: false, \
// RUN:     bugprone-record-ptr-cast.IgnoreIfRecordIsFromSystemHeader: false \
// RUN:  }}' -- \
// RUN: -isystem %S/Inputs/record-ptr-cast/system

#include <pthread.h>

void fromSystemHeaderFile(pthread_mutex_t *T) {
  void *P = T; // CHECK-MESSAGES: :[[@LINE]]:13: warning: invalid cast from 'pthread_mutex_t *' to 'void *'
  (void*) T; // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'pthread_mutex_t *' to 'void *'
}
