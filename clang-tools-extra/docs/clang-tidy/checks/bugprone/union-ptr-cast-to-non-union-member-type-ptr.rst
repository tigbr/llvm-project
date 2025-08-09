.. title:: clang-tidy - bugprone-union-ptr-cast

bugprone-union-ptr-cast
=======================

Gives warnings for implicit, C-style and ``reinterpret_cast``s between pointers,
where the source is a pointer to a ``union``, and that ``union`` has no field
with the same type as target's pointee type.

.. code-block:: c++

  union MyUnion {
    int i;
    float f;
  };

  void example(union MyUnion *U) {
     int   *i = U;
     float *f = U;
     short *s = U; // warning: the union pointed to by this expression has no field with the type 'short'

     (int*)   U;
     (float*) U;
     (short*) U; // warning: the union pointed to by this expression has no field with the type 'short'

     reinterpret_cast<int*>(U);
     reinterpret_cast<float*>(U);
     reinterpret_cast<short*>(U); // warning: there is no field with the type 'short' in this union
  }

The check is aware of C++ inheritance. It allows casts to a base class from
a derived pointer.

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

.. option:: AlwaysAllowCastToPtrToChar, AlwaysAllowCastToPtrToVoid

Always allowing casts to ``char*`` and ``void*`` can be toggled with the
`AlwaysAllowCastToPtrToChar` and `AlwaysAllowCastToPtrToVoid` options.

Both are enabled by default.

.. option:: AllowUnderlyingType

This option toggles the behavior how to handle when one of the union fields
has an aliased type, i.e. typedef or using. When this option is enabled, 

Example:

.. code-block:: C

  typedef PtrToShort *short;

  union MyUnion {
    PtrToShort pts;
  };
