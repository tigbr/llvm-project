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

static const struct {
	std::string_view AllowCastToVoidPtr = "AllowCastToVoidPtr";
	std::string_view AllowCastToCharPtr = "AllowCastToCharPtr";
} OptionNames;

static const struct {
	std::string_view Union = "union";
	std::string_view Cast = "cast";
} BindNames;

/// FIXME: Write a short description.
///
/// For the user-facing documentation see:
/// http://clang.llvm.org/extra/clang-tidy/checks/bugprone/union-ptr-cast-to-non-union-member-ptr.html
class UnionPtrCastToNonUnionMemberTypePtrCheck : public ClangTidyCheck {

  const bool AllowCastToVoidPtr;
  const bool AllowCastToCharPtr;

public:
  UnionPtrCastToNonUnionMemberTypePtrCheck(StringRef Name, ClangTidyContext *Context)
    : ClangTidyCheck(Name, Context),
      AllowCastToVoidPtr(Options.get(OptionNames.AllowCastToVoidPtr, false)),
      AllowCastToCharPtr(Options.get(OptionNames.AllowCastToCharPtr, false)) { }

  void registerMatchers(ast_matchers::MatchFinder *Finder) override;
  void check(const ast_matchers::MatchFinder::MatchResult &Result) override;
};

} // namespace clang::tidy::bugprone

#endif // LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_BUGPRONE_UNIONPTRCASTTONONUNIONMEMBERPTRCHECK_H
