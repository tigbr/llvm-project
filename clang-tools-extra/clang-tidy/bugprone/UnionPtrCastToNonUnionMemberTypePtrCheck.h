//===--- UnionPtrCastToNonUnionMemberPtrCheck.h - clang-tidy ----*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_BUGPRONE_UNIONPTRCASTTONONUNIONMEMBERPTRCHECK_H
#define LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_BUGPRONE_UNIONPTRCASTTONONUNIONMEMBERPTRCHECK_H

#include "../ClangTidyCheck.h"

namespace clang::tidy::bugprone {

static constexpr llvm::StringLiteral AllowCastToPtrToVoidOptionName = "AllowCastToPtrToVoid";
static constexpr llvm::StringLiteral AllowCastToPtrToCharOptionName = "AllowCastToPtrToChar";
static constexpr llvm::StringLiteral UnionBindName = "union";
static constexpr llvm::StringLiteral CastBindName = "cast";

/// FIXME: Write a short description.
///
/// For the user-facing documentation see:
/// http://clang.llvm.org/extra/clang-tidy/checks/bugprone/union-ptr-cast-to-non-union-member-ptr.html
class UnionPtrCastToNonUnionMemberTypePtrCheck : public ClangTidyCheck {
  const bool AllowCastToPtrToVoid;
  const bool AllowCastToPtrToChar;
public:
  UnionPtrCastToNonUnionMemberTypePtrCheck(StringRef Name, ClangTidyContext *Context)
    : ClangTidyCheck(Name, Context),
      AllowCastToPtrToVoid(Options.get(AllowCastToPtrToVoidOptionName, true)),
      AllowCastToPtrToChar(Options.get(AllowCastToPtrToCharOptionName, true)) { }

  bool isLanguageVersionSupported(const LangOptions &LangOpts) const override;
  void registerMatchers(ast_matchers::MatchFinder *Finder) override;
  void check(const ast_matchers::MatchFinder::MatchResult &Result) override;
  void process(const RecordDecl *Union, const CastExpr *Cast, QualType pointee_qualtype);
};

} // namespace clang::tidy::bugprone

#endif // LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_BUGPRONE_UNIONPTRCASTTONONUNIONMEMBERPTRCHECK_H
