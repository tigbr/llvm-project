//===--- UnionPtrCastCheck.h - clang-tidy -----------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_BUGPRONE_UNIONPTRCASTCHECK_H
#define LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_BUGPRONE_UNIONPTRCASTCHECK_H

#include "../ClangTidyCheck.h"

namespace clang::tidy::bugprone {

/// Gives warnings for implicit cast, C-style cast and `reinterpret_cast`
/// expressions between pointers, where the source type is a pointer to
/// a `union`, and that `union` has no field with the same type as the
/// target's pointee type.
///
/// For the user-facing documentation see:
/// http://clang.llvm.org/extra/clang-tidy/checks/bugprone/union-ptr-cast.html
class UnionPtrCastCheck : public ClangTidyCheck {
public:
  UnionPtrCastCheck(StringRef Name, ClangTidyContext *Context);
  bool isLanguageVersionSupported(const LangOptions &LangOpts) const override;
  void registerMatchers(ast_matchers::MatchFinder *Finder) override;
  void check(const ast_matchers::MatchFinder::MatchResult &Result) override;

private:
  const bool AllowCastToBaseClass;
  const bool AllowCastToSubField;
  const bool AlwaysAllowCastToCharPtr;
  const bool AlwaysAllowCastToVoidPtr;
  const bool CompareCanonicalTypes;
  const bool IgnoreIfUnionIsFromStdNamespace;
  const bool IgnoreIfUnionIsFromSystemHeader;

  bool hasFieldOfType(const PointerType *Target, const RecordDecl *Record) const;
  bool shouldWarn(const PointerType *CastTargetPointerType, const RecordDecl *Union) const;
};

} // namespace clang::tidy::bugprone

#endif // LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_BUGPRONE_UNIONPTRCASTCHECK_H
