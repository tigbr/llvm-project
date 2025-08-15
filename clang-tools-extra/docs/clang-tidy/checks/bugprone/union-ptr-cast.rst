.. title:: clang-tidy - bugprone-union-ptr-cast

bugprone-union-ptr-cast
=======================

Gives warnings for implicit cast, C-style cast and ``reinterpret_cast``
expressions between pointers, where the source type is a pointer to a ``union``,
and that ``union`` has no field with the same type as the target's pointee type.

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
    reinterpret_cast<short*>(U); // warning: there is no field with the type 'short' in this union
    reinterpret_cast<double*>(U); // warning: there is no field with the type 'double' in this union
  }

The check is aware of C++ inheritance. It accepts casts where the ``union`` has a field whose type is a subtype of the cast target pointee type and does not have a field with exactly the cast target pointee type.

.. code-block:: c++

  class Base { };
  class Derived : public Base { };

  union MyUnion {
    Derived *D;
  };

  void foo(union MyUnion *U) {
    Base *B;
    B = U;
    B = (Base*) U;
    B = reinterpret_cast<Base*>(U);
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

