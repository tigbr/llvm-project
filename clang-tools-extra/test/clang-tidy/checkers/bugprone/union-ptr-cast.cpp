// RUN: %check_clang_tidy -std=c++98-or-later %s bugprone-union-ptr-cast-to-non-union-member-type-ptr %t

typedef short *short_ptr_typedef;
using short_ptr_using = short*;

union MyUnion {
    short s;
    float f;
    short_ptr_typedef spt;
    short_ptr_using spu;
};

// Implicit casts like char *c = &MyUnion are compile-time errors in C++.
// These cases are included only in the C test file.

void analyzedAndAllowed(union MyUnion *u) {
    (short*) u;
    (float*) u;
    (short_ptr_typedef*) u;
    (short_ptr_using*) u;

    reinterpret_cast<short*>(u);
    reinterpret_cast<float*>(u);
    reinterpret_cast<short_ptr_typedef*>(u);
    reinterpret_cast<short_ptr_using*>(u);

    union MyUnion *u2 = u;
    (union MyUnion*) u;
    reinterpret_cast<union MyUnion*>(u);
}

void option_dependent_default_behaviors(union MyUnion *u) {
    // This implicit cast does not give an error in C++ mode so it included here
    void *v = u;

    (char*) u;
    (void*) u;

    reinterpret_cast<char*>(u);
    reinterpret_cast<void*>(u);
}

void bad_cast_with_known_union_definition(union MyUnion *u) {
    (long*) u;             // CHECK-MESSAGES: :[[@LINE]]:13: warning: the union pointed to by this expression has no field with the type 'long'

    // It does not matter that the union has a field with the same type
    // as the aliased type. Typedefs and usings are not considered "transparent"
    // in that sense.
    (short_ptr_typedef) u; // CHECK-MESSAGES: :[[@LINE]]:25: warning: the union pointed to by this expression has no field with the type 'short_ptr_typedef'
    (short_ptr_using)   u; // CHECK-MESSAGES: :[[@LINE]]:25: warning: the union pointed to by this expression has no field with the type 'short_ptr_using'

    reinterpret_cast<long*>(u);             // CHECK-MESSAGES: :[[@LINE]]:29: warning: the union pointed to by this expression has no field with the type 'long'
    reinterpret_cast<short_ptr_typedef>(u); // CHECK-MESSAGES: :[[@LINE]]:41: warning: the union pointed to by this expression has no field with the type 'short_ptr_typedef'
    reinterpret_cast<short_ptr_using>(u);   // CHECK-MESSAGES: :[[@LINE]]:39: warning: the union pointed to by this expression has no field with the type 'short_ptr_using'
}

void bad_cast_with_unknown_union_definition(union Unknown *u) {
    (char*)   u; // CHECK-MESSAGES: :[[@LINE]]:15: warning: the union pointed to by this expression has no field with the type 'char'
    (short*)  u; // CHECK-MESSAGES: :[[@LINE]]:15: warning: the union pointed to by this expression has no field with the type 'short'
    (int*)    u; // CHECK-MESSAGES: :[[@LINE]]:15: warning: the union pointed to by this expression has no field with the type 'int'
    (long*)   u; // CHECK-MESSAGES: :[[@LINE]]:15: warning: the union pointed to by this expression has no field with the type 'long'
    (float*)  u; // CHECK-MESSAGES: :[[@LINE]]:15: warning: the union pointed to by this expression has no field with the type 'float'
    (double*) u; // CHECK-MESSAGES: :[[@LINE]]:15: warning: the union pointed to by this expression has no field with the type 'double'

    reinterpret_cast<char*>  (u); // CHECK-MESSAGES: :[[@LINE]]:31: warning: the union pointed to by this expression has no field with the type 'char'
    reinterpret_cast<short*> (u); // CHECK-MESSAGES: :[[@LINE]]:31: warning: the union pointed to by this expression has no field with the type 'short'
    reinterpret_cast<int*>   (u); // CHECK-MESSAGES: :[[@LINE]]:31: warning: the union pointed to by this expression has no field with the type 'int'
    reinterpret_cast<long*>  (u); // CHECK-MESSAGES: :[[@LINE]]:31: warning: the union pointed to by this expression has no field with the type 'long'
    reinterpret_cast<float*> (u); // CHECK-MESSAGES: :[[@LINE]]:31: warning: the union pointed to by this expression has no field with the type 'float'
    reinterpret_cast<double*>(u); // CHECK-MESSAGES: :[[@LINE]]:31: warning: the union pointed to by this expression has no field with the type 'double'
}

void casts_that_should_not_be_analyzed() {
    long li;
	unsigned long ul = li;
	(unsigned long) li;
    // Already an error at compile time
    // reinterpret_cast<unsigned long>(li);

    (void*) li;
    reinterpret_cast<void*>(li);

    class Base { };
    class Derived : public Base { };
    Base *B;
    Derived *D;
    B = D;
    B = (Base*) D;
    B = reinterpret_cast<Base*>(D);
    B = static_cast<Base*>(D);
}
