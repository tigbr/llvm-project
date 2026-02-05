//===--- RecordPtrCastCheck.h - clang-tidy ----------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_BUGPRONE_RECORDPTRCASTCHECK_H
#define LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_BUGPRONE_RECORDPTRCASTCHECK_H

#include "../ClangTidyCheck.h"

namespace clang::tidy::bugprone {

/// Checks implicit cast, C-style cast and `reinterpret_cast` expressions
/// that convert a `struct`, a `class` or a `union` pointer.
///
/// For the user-facing documentation see:
/// http://clang.llvm.org/extra/clang-tidy/checks/bugprone/record-ptr-cast.html
class RecordPtrCastCheck : public ClangTidyCheck {
public:
  RecordPtrCastCheck(StringRef Name, ClangTidyContext *Context);
  bool isLanguageVersionSupported(const LangOptions &LangOpts) const override;
  void registerMatchers(ast_matchers::MatchFinder *Finder) override;
  void check(const ast_matchers::MatchFinder::MatchResult &Result) override;

private:
  const bool AlwaysAllowCastToCharPtr;
  const bool AlwaysAllowCastToVoidPtr;
  const bool CompareCanonicalTypes;
  const bool IgnoreIfRecordIsFromStdNamespace;
  const bool IgnoreIfRecordIsFromSystemHeader;

  void emitWarning(const CastExpr *Cast, QualType CastQT,
                   const ast_matchers::MatchFinder::MatchResult &Result);
  bool notStandardLayoutIfCPP(const RecordDecl *d) const;
  bool castToAllowedPrimitiveTypePtr(const PointerType *Target) const;
  bool hasFieldOfType(const PointerType *Target, const RecordDecl *Record,
                      const ASTContext *AST) const;
};

} // namespace clang::tidy::bugprone

#endif // LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_BUGPRONE_RECORDPTRCASTCHECK_H
