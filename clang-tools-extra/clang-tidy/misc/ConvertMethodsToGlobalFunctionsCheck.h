//===--- ConvertMethodsToGlobalFunctionsCheck.h - clang-tidy ----*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_MISC_CONVERTMETHODSTOGLOBALFUNCTIONSCHECK_H
#define LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_MISC_CONVERTMETHODSTOGLOBALFUNCTIONSCHECK_H

#include "../ClangTidyCheck.h"
#include "../utils/IncludeInserter.h"

namespace clang::tidy::misc {

/// FIXME: Write a short description.
///
/// For the user-facing documentation see:
/// http://clang.llvm.org/extra/clang-tidy/checks/misc/convert-methods-to-global-functions.html
class ConvertMethodsToGlobalFunctionsCheck : public ClangTidyCheck {
  clang::tidy::utils::IncludeInserter inserter;
public:
  ConvertMethodsToGlobalFunctionsCheck(StringRef Name, ClangTidyContext *Context)
      : ClangTidyCheck(Name, Context), 
        inserter(Options.getLocalOrGlobal("IncludeStyle", utils::IncludeSorter::IS_LLVM), areDiagsSelfContained()) {}
  void registerMatchers(ast_matchers::MatchFinder *Finder) override;
  void check(const ast_matchers::MatchFinder::MatchResult &Result) override;
  bool isLanguageVersionSupported(const LangOptions &LangOpts) const override;
  void registerPPCallbacks(const SourceManager &SM, Preprocessor *PP,
                                   Preprocessor *ModuleExpanderPP) override;
};

} // namespace clang::tidy::misc

#endif // LLVM_CLANG_TOOLS_EXTRA_CLANG_TIDY_MISC_CONVERTMETHODSTOGLOBALFUNCTIONSCHECK_H
