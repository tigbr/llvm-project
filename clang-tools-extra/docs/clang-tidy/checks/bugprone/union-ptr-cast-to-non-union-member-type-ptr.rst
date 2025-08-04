.. title:: clang-tidy - bugprone-union-ptr-cast-to-non-union-member-ptr

bugprone-union-ptr-cast-to-non-union-member-type-ptr
====================================================

Gives warnings for C-style and implicit casts between pointers,
where the source is a pointer to a ``union``, and that ``union`` has no field
with the same type as the cast's target pointer's pointee type.

Example:

.. code-block:: c

  union MyUnion {
    int i;
    float f;
  };

  void foo(union MyUnion *U) {
     short *s = (short*) U; // warning: the union pointed to by 'U' has no member with the type 'short'
  }

Options
-------

Allowing casts to ``char*`` and ``void*`` can be toggled with the
`AllowCastToPtrToChar` and `AllowCastToPtrToVoid` options.

Both are enabled by default.

