// RUN: %check_clang_tidy -std=c++98-or-later %s bugprone-record-ptr-cast %t \
// RUN:   --config='{CheckOptions: { \
// RUN:     bugprone-record-ptr-cast.AlwaysAllowCastToVoidPtr: false, \
// RUN:     bugprone-record-ptr-cast.IgnoreIfRecordIsFromStdNamespace: false, \
// RUN:     bugprone-record-ptr-cast.IgnoreIfRecordIsFromSystemHeader: false \
// RUN:  }}' -- \
// RUN: -I%S/Inputs/record-ptr-cast \
// RUN: -isystem %S/Inputs/record-ptr-cast/system

#include "stdnamespace.h"
#include <pthread.h>

void fromStdNamespace(std::pthread_mutex_t *T) {
  void *P = T;                // CHECK-MESSAGES: :[[@LINE]]:13: warning: invalid cast from 'std::pthread_mutex_t *' to 'void *'
  (void*) T;                  // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'std::pthread_mutex_t *' to 'void *'
  reinterpret_cast<void*>(T); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'std::pthread_mutex_t *' to 'void *'
}

void fromSystemHeaderFile(pthread_mutex_t *T) {
  void *P = T;                // CHECK-MESSAGES: :[[@LINE]]:13: warning: invalid cast from 'pthread_mutex_t *' to 'void *'
  (void*) T;                  // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'pthread_mutex_t *' to 'void *'
  reinterpret_cast<void*>(T); // CHECK-MESSAGES: :[[@LINE]]:3: warning: invalid cast from 'pthread_mutex_t *' to 'void *'
}
