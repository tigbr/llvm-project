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

The check is aware of C++ inheritance. A cast is also accepted if the ``union`` has a field whose type is only a subtype of the cast target's pointee type.

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

The pointer may be hidden behind (potentially multiple) ``typedef`` or a ``using`` statements.

.. code-block:: c++

  typedef short *ShortPtr;

  union MyUnion {
    void *P;
    float F;
  };

  void example(union MyUnion *U) {
    ShortPtr S = (ShortPtr) U; // warning: the union pointed to by this expression has no field with the type 'short'
  }

Options
-------

.. option:: AlwaysAllowCastToCharPtr, AlwaysAllowCastToVoidPtr

These options toggle whether casts to ``char*`` or ``void*`` should be allowed,
even when the ``union`` pointed by the source expression does not contain a field with
one of those types.

Both are enabled by default.

.. option:: IgnoreIfUnionIsFromStdNamespace, IgnoreIfUnionIsFromSystemHeader

These options toggle whether a cast should be ignored when the ``union``
pointed by the source expression is declared in the ``std::`` namespace or in
a system header file.

Both are enabled by default.

