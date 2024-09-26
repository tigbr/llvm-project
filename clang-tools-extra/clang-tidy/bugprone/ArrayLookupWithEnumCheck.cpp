//===--- ArrayLookupWithEnumCheck.cpp - clang-tidy ------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "ArrayLookupWithEnumCheck.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"

using namespace clang::ast_matchers;

namespace clang::tidy::bugprone {

static const StringRef SubscriptBaseBindName = "base";
static const StringRef SubscriptIndexBindName = "index";
static const StringRef SubscriptExprBindName = "expr";

void ArrayLookupWithEnumCheck::registerMatchers(MatchFinder *Finder) {
  Finder->addMatcher(arraySubscriptExpr(allOf(hasBase(implicitCastExpr(hasSourceExpression(declRefExpr(hasType(arrayType())).bind(SubscriptBaseBindName)))), hasIndex(declRefExpr(hasDeclaration(enumConstantDecl())).bind(SubscriptIndexBindName)))).bind(SubscriptExprBindName), this);
}

void ArrayLookupWithEnumCheck::check(const MatchFinder::MatchResult &Result) {
  const auto *Base  = Result.Nodes.getNodeAs<DeclRefExpr>(SubscriptBaseBindName);
  const auto *Index = Result.Nodes.getNodeAs<DeclRefExpr>(SubscriptIndexBindName);
  const auto *SubscriptExpr = Result.Nodes.getNodeAs<ArraySubscriptExpr>(SubscriptExprBindName);
  diag(SubscriptExpr->getBeginLoc(), "Array lookup by enum constant!");
}

} // namespace clang::tidy::bugprone
