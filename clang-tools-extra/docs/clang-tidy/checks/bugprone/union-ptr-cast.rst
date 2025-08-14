.. title:: clang-tidy - bugprone-union-ptr-cast

bugprone-union-ptr-cast
=======================

Gives warnings for implicit cast, C-style cast and ``reinterpret_cast``
expressions between pointers, where the source is a pointer to a ``union``,
and that ``union`` has no field with the same type as target's pointee type.

.. code-block:: c++

  union MyUnion {
    int i;
    float f;
    volatile double d;
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

The check is aware of C++ inheritance. It allows casts to base class pointers.

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

Always allowing casts to ``char*`` and ``void*`` can be toggled with the
`AlwaysAllowCastToPtrToChar` and `AlwaysAllowCastToPtrToVoid` options.

Both are enabled by default.

.. option:: AnalyzeUnionsFromStdNamespace, AnalyzeUnionsFromSystemHeaders

These options toggle whether a cast should be analyzed where the ``union``
pointed to by the source expression comes from the ``std::`` namespace or from a
system header file.

Both are disabled by default.

