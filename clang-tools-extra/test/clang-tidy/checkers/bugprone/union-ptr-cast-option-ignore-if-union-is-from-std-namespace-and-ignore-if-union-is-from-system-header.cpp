// RUN: %check_clang_tidy -std=c++98-or-later %s bugprone-union-ptr-cast %t \
// RUN:   --config='{CheckOptions: { \
// RUN:     bugprone-union-ptr-cast.AlwaysAllowCastToVoidPtr: false, \
// RUN:     bugprone-union-ptr-cast.IgnoreIfUnionIsFromStdNamespace: false, \
// RUN:     bugprone-union-ptr-cast.IgnoreIfUnionIsFromSystemHeader: false \
// RUN:  }}' -- \
// RUN: -I%S/Inputs/union-ptr-cast \
// RUN: -isystem %S/Inputs/union-ptr-cast/system

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
