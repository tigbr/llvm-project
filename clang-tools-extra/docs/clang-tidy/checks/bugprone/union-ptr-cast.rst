.. title:: clang-tidy - bugprone-union-ptr-cast

bugprone-union-ptr-cast
=======================

Checks implicit cast, C-style cast and ``reinterpret_cast`` expressions
that convert a ``struct``, a ``class`` or a ``union`` pointer.

.. code-block:: c++

  union MyUnion {
    int I;
    float F;
    volatile double VD;
  };

  void example(union MyUnion *U) {
    int   *I = U;
    float *F = U;
    short *S = U; // warning: invalid cast from 'union MyUnion *' to 'short *'
    double *D = U; // warning: invalid cast from 'union MyUnion *' to 'double *'

    (int*)   U;
    (float*) U;
    (short*) U; // warning: invalid cast from 'union MyUnion *' to 'short *'
    (double*) U; // warning: invalid cast from 'union MyUnion *' to 'double *'

    reinterpret_cast<int*>(U);
    reinterpret_cast<float*>(U);
    reinterpret_cast<short*>(U); // warning: invalid cast from 'union MyUnion *' to 'short *'
    reinterpret_cast<double*>(U); // warning: invalid cast from 'union MyUnion *' to 'double *'
  }

In case the target pointer type of the cast is behind a type alias,
then the check retrieves the pointer type itself from behind the alias.
In the example below, the check retrieves the type behind ``(ShortPtr)``,
namely, ``short *``.

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

.. option:: AllowCastToBaseClass

This option is enabled by default.

When enabled, the check becomes aware of C++ inheritance. This means that casts
are also accepted when the ``union`` contains a field whose type is a subtype
of the cast target's pointee type.

.. code-block:: c++

  class Base { /* ... */ };
  class Derived : public Base { /* ... */ };

  union MyUnion {
    Derived D;
  };

  void example(union MyUnion *U) {
    Base *B;
    // No warning, despite MyUnion not having a field with the type B,
    // as the pointee type of B is an ancestor type of field D's type.
    B = (Base*) U;
    B = reinterpret_cast<Base*>(U);
  }

.. option:: AlwaysAllowCastToCharPtr, AlwaysAllowCastToVoidPtr

Both are enabled by default.

These options toggle whether casts to ``char*`` or ``void*`` should be allowed
even when the ``union`` pointed by the source expression does not contain a
field with one of those types.

.. option:: CompareCanonicalTypes

This option is disabled by default.

When enabled, the check compares the canonical versions of the pointer pointee
and the ``union`` field types. This means that the types are converted to their
most fundamental form by removing all sugar, ``typedef``, ``using`` etc. layers.
This operation preserves the levels of indirection and the qualifiers introduced
by the type aliases.

This option can be useful, for instance, when the type aliases in question are
just shorthands, such as ``typedef unsigned int uint;``, and they do not carry
any semantic information, like ``pid_t`` does for instance.

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

.. option:: IgnoreIfUnionIsFromStdNamespace, IgnoreIfUnionIsFromSystemHeader

Both are enabled by default.

These options toggle whether a cast should be ignored when the ``union``
pointed by the source expression is declared in the ``std::`` namespace or in
a system header file.
