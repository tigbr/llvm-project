//===--- UnionPtrCastCheck.h - clang-tidy ----*- C++ -*-===//
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

/// FIXME: Write a short description.
///
/// For the user-facing documentation see:
/// http://clang.llvm.org/extra/clang-tidy/checks/bugprone/union-ptr-cast-to-non-union-member-ptr.html
class UnionPtrCastCheck : public ClangTidyCheck {
  const bool AlwaysAllowCastToPtrToVoid;
  const bool AlwaysAllowCastToPtrToChar;
  const bool HandleAliasedTypesStrictly;
public:
  UnionPtrCastCheck(StringRef Name, ClangTidyContext *Context);
  bool isLanguageVersionSupported(const LangOptions &LangOpts) const override;
  void registerMatchers(ast_matchers::MatchFinder *Finder) override;
  void check(const ast_matchers::MatchFinder::MatchResult &Result) override;
  void AnalyzeCast(const RecordDecl *Union, const Expr *SubExpression, QualType PointeeQualType);
};

} // namespace clang::tidy::bugprone

#endif // LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_BUGPRONE_UNIONPTRCASTTONONUNIONMEMBERPTRCHECK_H
