.. title:: clang-tidy - bugprone-union-ptr-cast-to-non-union-member-ptr

bugprone-union-ptr-cast-to-non-union-member-type-ptr
====================================================

Gives warnings for casts between two pointers, where the source is a pointer to
a ``union``, and there is no member in that ``union`` whose type is the same as
the target pointers pointee type.

Example:

.. code-block:: c

  union MyUnion {
    int i;
    float f;
  };

  void foo(union MyUnion *U) {
     short *s = (short*) U; // Warning: MyUnion has no member with the type short 
  }

The check analyzes only C-style casts and implicit casts.

Options
-------

The check can be configured to always allow casts to ``char*`` and ``void*`` with the 
options `AllowCastToPtrToChar` and `AllowCastToPtrToVoid`.

Both of these are disabled by default.

