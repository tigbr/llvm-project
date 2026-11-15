// RUN: %check_clang_tidy %s readability-always-dereferenced-variable %t -- -- -I %S/Inputs/always-dereferenced-variable

// Tests for raw pointers

bool f(int *a) {
	return a == nullptr;
}

// Always dereferenced
void g1(int *a) {
	*a;
	a[0];
	0[a];
}

bool g2(int *a) {
	return *a == -4;
}

struct S { int x; };

void g3(struct S *s) {
	*s;
	s[0];
	0[s];
	s->x;
}

void g4(void (*f)(void)) {
	(*f)();
	// (f[0])(); // function pointer subscription is invalid
	// (0[f])(); // function pointer subscription is invalid
}

void g5(void (*f)(void)) {
	f();
}

void g6(int x) {
	int *a = &x;
	*a;
	a[0];
	0[a];
}

#include "optional.h"

struct S { int x; };

void parameter(std::optional<struct S> my_optional) { // CHECK-MESSAGES: :[[@LINE]]:40: warning: this std::optional is always dereferenced, consider using the underlying type directly
  my_optional.value();
  *my_optional;
  my_optional->x;
}

void variable() {
  std::optional<struct S> my_optional; // CHECK-MESSAGES: :[[@LINE]]:27: warning: this std::optional is always dereferenced, consider using the underlying type directly
  my_optional.value();
  *my_optional;
  my_optional->x;
}
