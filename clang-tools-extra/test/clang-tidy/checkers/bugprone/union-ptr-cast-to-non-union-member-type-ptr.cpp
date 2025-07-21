// RUN: %check_clang_tidy %s bugprone-union-ptr-cast-to-non-union-member-type-ptr %t

typedef short *short_ptr;

union {
    short s;
    float f;
    short_ptr ptr;
} u;

void always_allowed() {
    short *s = (short*) &u;
    float *f = (float*) &u;
}

// Pointer to union is cast to pointer with a pointee type which is not contained in the union!
void always_reported() {
    long *l = (long*) &u;           // CHECK-MESSAGES: :[[@LINE]]:15: warning: bad
    short_ptr ptr = (short_ptr) &u; // CHECK-MESSAGES: :[[@LINE]]:21: warning: bad
}

void default_options() {
    char *c = (char*) &u;
    void *v = (void*) &u;
}

