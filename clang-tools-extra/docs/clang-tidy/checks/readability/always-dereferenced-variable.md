```{title} clang-tidy - readability-always-dereferenced-variable
```

# readability-ambiguous-smartptr-reset-call

Detects always dereferenced pointer or `std::optional` variables in C++.

In the case of pointers, the check suggests the use of a reference, whereas
for `std::optional<T>` variables, it recommends to use the type T directly.

