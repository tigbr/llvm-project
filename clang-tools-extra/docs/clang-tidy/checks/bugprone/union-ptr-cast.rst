.. title:: clang-tidy - bugprone-union-ptr-cast

bugprone-union-ptr-cast
=======================

Gives warnings for implicit cast, C-style cast and ``reinterpret_cast``
expressions between pointers, where the source type is a pointer to
a ``union``, and that ``union`` has no field with the same type as the
target's pointee type.

.. code-block:: c++

  union MyUnion {
    int I;
    float F;
    volatile double VD;
  };

  void example(union MyUnion *U) {
    int   *I = U;
    float *F = U;
    short *S = U; // warning: the union pointed to by this expression has no field with the type 'short'
    double *D = U; // warning: the union pointed to by this expression has no field with the type 'double'

    (int*)   U;
    (float*) U;
    (short*) U; // warning: the union pointed to by this expression has no field with the type 'short'
    (double*) U; // warning: the union pointed to by this expression has no field with the type 'double'

    reinterpret_cast<int*>(U);
    reinterpret_cast<float*>(U);
    reinterpret_cast<short*>(U); // warning: the union pointed to by this expression has no field with the type 'short'
    reinterpret_cast<double*>(U); // warning: the union pointed to by this expression has no field with the type 'double'
  }

The check can retrieve the pointee target type through type aliases.
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
    (IntPtr) U; // warning: the union pointed to by this expression has no field with the type 'int'
  }

Options
-------

.. option:: AllowCastToBaseClass

This option is enabled by default.

When enabled, the check becomes aware of C++ inheritance. A cast is also
accepted if the ``union`` has a field whose type is a subtype of the cast
target's pointee type.

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

.. option:: AllowCastToSubField (C only)

This option is enabled by default.

Further 

.. option:: AlwaysAllowCastToCharPtr, AlwaysAllowCastToVoidPtr

Both are enabled by default.

These options toggle whether casts to ``char*`` or ``void*`` should be allowed
even when the ``union`` pointed by the source expression does not contain a
field with one of those types.

.. option:: IgnoreIfUnionIsFromStdNamespace, IgnoreIfUnionIsFromSystemHeader

Both are enabled by default.

These options toggle whether a cast should be ignored when the ``union``
pointed by the source expression is declared in the ``std::`` namespace or in
a system header file.

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
