// RUN: %check_clang_tidy %s bugprone-union-ptr-cast-to-non-union-member-ptr %t

typedef long **lpp;

void f() {
    union {
        short s;
        float f;
    } u;

    // Pointer to union is cast to pointer with pointee type which is not contained in the union!
    // CHECK-MESSAGES: :[[@LINE+1]]:16: warning: bad
    long  *l = (long*)  &u;
    short *s = (short*) &u;
    float *f = (float*) &u;
    char  *c = (char*)  &u;
    void  *v = (void*)  &u;
}
