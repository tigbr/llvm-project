// RUN: %check_clang_tidy %s bugprone-union-ptr-cast-to-non-union-member-type-ptr %t

typedef short *short_ptr;

void f() {
    union {
        short s;
        float f;
    } u;

    short *s = (short*) &u;
    float *f = (float*) &u;

    // Pointer to union is cast to pointer with pointee type which is not contained in the union!
    // CHECK-MESSAGES: :[[@LINE+1]]:16: warning: bad
    long  *l = (long*)  &u;

    // CHECK-MESSAGES: :[[@LINE+1]]:16: warning: bad
    char  *c = (char*)  &u;

    // CHECK-MESSAGES: :[[@LINE+1]]:16: warning: bad
    void  *v = (void*)  &u;

    // CHECK-MESSAGES: :[[@LINE+1]]:16: warning: bad
    short_ptr ptr = (short_ptr) &u;

    void *v2 = &u;

    char *c2 = &u;
}
