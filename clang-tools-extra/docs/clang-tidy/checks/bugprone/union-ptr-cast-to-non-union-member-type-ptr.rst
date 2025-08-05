.. title:: clang-tidy - bugprone-union-ptr-cast-to-non-union-member-ptr

bugprone-union-ptr-cast-to-non-union-member-type-ptr
====================================================

Gives warnings for C-style and implicit casts between pointers, where
the source is a pointer to a ``union``, and that ``union`` has no field
with the same type as target's pointee type.

Example:

.. code-block:: c

  union MyUnion {
    int i;
    float f;
  };

  void foo(union MyUnion *U) {
     int   *i = (int*)   U;
     float *f = (float*) U;
     short *s = (short*) U; // warning: the union pointed to by this expression has no field with the type 'short'
  }

Options
-------

Always allowing casts to ``char*`` and ``void*`` can be toggled with the
`AlwaysAllowCastToPtrToChar` and `AlwaysAllowCastToPtrToVoid` options.

Both are enabled by default.

