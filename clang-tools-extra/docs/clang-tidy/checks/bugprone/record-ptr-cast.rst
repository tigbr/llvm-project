.. title:: clang-tidy - bugprone-record-ptr-cast

bugprone-record-ptr-cast
========================

Checks implicit cast, C-style cast and ``reinterpret_cast`` expressions
that convert a ``struct``, a ``class`` or a ``union`` pointer.

Casting a pointer to a ``struct`` or a pointer to a ``union`` object has
the following two properties according to the ANSI C standard section
``3.2.5.1 Structure and Union Specifiers``:

  A pointer to a structure object, suitably converted, points to its initial
  member (or if that member is a bit-held, then to the unit in which it
  resides), and vice versa.

  A pointer to a union object, suitably converted, points to each of its members
  (or if a member is a bit-held, then to the unit in which it resides), and vice
  versa.

These rules have their analogous versions in later C standards, and also in C++
standards. Note, however, that in C++ they only apply to ``standard-layout``
objects.

This check analyzes these kinds of conversions for mistakes.

Examples
--------

The cast target pointee type should be equivalent to the initial member's type in case of ``struct`` and ``class`` objects, and to any member's type in case of ``union`` objects.

.. code-block:: c++

  struct MyStruct {
    int I;
    float F;
  };
  
  class MyClass {
    int I;
    float F;
  };
  
  union MyUnion {
    int I;
    float F;
  };
  
  void example(struct MyStruct *S, class MyClass *C, union MyUnion *U) {
    (int*)   S;
    (float*) S; // warning: invalid cast from 'struct MyStruct *' to 'float *'
    (short*) S; // warning: invalid cast from 'struct MyStruct *' to 'short *'
  
    (int*)   C;
    (float*) C; // warning: invalid cast from 'class MyClass *' to 'short *'
    (short*) C; // warning: invalid cast from 'class MyClass *' to 'short *'
  
    (int*)   U;
    (float*) U;
    (short*) U; // warning: invalid cast from 'union MyUnion *' to 'short *'
  }

The aforementioned rules are recursively applicable to the subobjects as well.

.. code-block:: c++

  struct Bar {
    void *V;
  };
  
  struct Foo {
    struct Bar B;
    double D;
  };
  
  union MyUnion {
    struct Foo F;
  };
  
  void example(union MyUnion *U) {
    (struct Foo *) U; // (union MyUnion *) -> (struct Foo *)
    (struct Bar *) U; // (union MyUnion *) -> (struct Foo *) -> (struct Bar *)
    (void**) U;       // (union MyUnion *) -> (struct Foo *) -> (struct Bar *) -> (void**)
  
    (double *) U; // warning: invalid cast from 'union MyUnion *' to 'double *'
  }

It allows adding and disallows discarding of qualifiers.

.. code-block:: c++

  union MyUnion {
    const volatile int I;
    volatile float F;
    const long L;
    double D;
  };
  
  void example(union MyUnion *U) {
    (int*) U;          // warning: invalid cast from 'union MyUnion *' to 'int *'
    (const int*) U;    // warning: invalid cast from 'union MyUnion *' to 'const int *'
    (volatile int*) U; // warning: invalid cast from 'union MyUnion *' to 'volatile int *'
    (const volatile int*) U;
  
    (float*) U;          // warning: invalid cast from 'union MyUnion *' to 'float *'
    (const float*) U;    // warning: invalid cast from 'union MyUnion *' to 'const float *'
    (volatile float*) U;
    (const volatile float*) U;
  
    (long*) U;          // warning: invalid cast from 'union MyUnion *' to 'long *'
    (const long*) U;    
    (volatile long*) U; // warning: invalid cast from 'union MyUnion *' to 'volatile long *'
    (const volatile long*) U;
  
    (double*) U;
    (const double*) U;
    (volatile double*) U;
    (const volatile double*) U;
  }

In case the target pointer type of the cast is behind a type alias,
then the check retrieves the pointer type itself from behind the alias.
In the example below, ``short *`` and ``int *`` are retrieved from behind
their respective aliases ``ShortPtr`` and ``IntPtr``.

.. code-block:: c++

  typedef short *ShortPtr;
  typedef int *IntPtr;

  union MyUnion {
    short S;
  };

  void example(union MyUnion *U) {
    (ShortPtr) U;
    (IntPtr) U; // warning: invalid cast from 'union MyUnion *' to 'int *'
  }

Options
-------

.. option:: AlwaysAllowCastToCharPtr, AlwaysAllowCastToVoidPtr

Both options are set to ``true`` by default.

These options toggle whether casts to ``char*`` or ``void*`` should be allowed
even when the record type pointed by the source expression does not contain a
suitable field with one of those types.

.. option:: CompareCanonicalTypes

This option is set to ``false`` by default.

When enabled, the check compares the canonical versions of the pointer pointee
and the ``union`` field types. This means that the types are converted to their
most fundamental form by removing all sugar, ``typedef``, ``using`` etc. layers.
This operation preserves the levels of indirection and the qualifiers introduced
by the type aliases.

This option can be useful, for instance, when the type aliases in question are
just shorthands and do not carry any semantic information, such as
``typedef unsigned int uint;``.

The following example shows a few different examples for how this option affects
the interpretation of types.

.. code-block:: c++

  typedef short *ShortPtr;
  typedef ShortPtr *ShortPtrPtr;
  typedef const ShortPtr *ShortPtrConstPtr;

  struct Foo { int a; };
  typedef struct foo FooStruct;
  typedef FooStruct* FooStructPtr;

  typedef void (voidFunction)(ShortPtr, ShortPtrPtr);

+-----------------------+----------------------+-------------------------------+
| CompareCanonicalTypes | false (only desugar) |             true              |
+=======================+======================+===============================+
| `ShortPtr`            | `short *`            | `short *`                     |
+-----------------------+----------------------+-------------------------------+
| `ShortPtrConstPtr`    | `const ShortPtr *`   | `short *const *`              |
+-----------------------+----------------------+-------------------------------+
| `ShortPtrPtr`         | `ShortPtr *`         | `short **`                    |
+-----------------------+----------------------+-------------------------------+
| `voidFunction *`      | `voidFunction *`     | `void (*)(short *, short **)` |
+-----------------------+----------------------+-------------------------------+
| `FooStruct *`         | `FooStruct *`        | `struct foo *`                |
+-----------------------+----------------------+-------------------------------+
| `FooStructPtr`        | `FooStruct *`        | `struct foo *`                |
+-----------------------+----------------------+-------------------------------+

.. option:: IgnoreIfRecordIsFromStdNamespace, IgnoreIfRecordIsFromSystemHeader

Both options are set to ``true`` by default.

These options toggle whether a cast should be ignored when the record type
pointed by the source expression is declared in the ``std::`` namespace or
in a system header file.
