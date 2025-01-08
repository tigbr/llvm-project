//===--- MyfirstcheckCheck.cpp - clang-tidy -------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "YodaConditionCheck.h"
#include "clang/AST/Expr.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/Basic/Diagnostic.h"
#include "clang/Basic/LangOptions.h"
#include "clang/Lex/Lexer.h"
#include "llvm/ADT/StringRef.h"

using namespace clang::ast_matchers;

namespace clang::tidy::bugprone {

/*
    My Notes:
    bind can bind to sub results of a match!
    m mapAnyOf(ifStmt, whileStmt, forStmt, doStmt).with(hasCondition(binaryOperator(hasAnyOperatorName("==", "!=", "<=", ">=") ,
    hasLHS(hasDescendant(declRefExpr(to(varDecl( ) ) ) ) ), unless(hasRHS(hasDescendant(declRefExpr(to(varDecl( ) ) ) ) ) ) ).bind("myBind") ) )
*/

void YodaConditionCheck::registerMatchers(MatchFinder *Finder) {
  // FIXME: Add matchers.
  Finder->addMatcher(
	mapAnyOf(ifStmt, whileStmt, forStmt, doStmt) .with( hasCondition( binaryOperator( hasAnyOperatorName("==", "!=", "<=", ">="), hasLHS(hasDescendant(declRefExpr(to(varDecl() ) ) ) ), unless( hasRHS(hasDescendant(declRefExpr(to(varDecl() ) ) ) ) ) ).bind("myBind") ) ), this);
}

void YodaConditionCheck::check(const MatchFinder::MatchResult &Result) {
  // FIXME: Add callback implementation.
  const clang::LangOptions &LangOpts = getLangOpts();
  const auto *MatchedDecl = Result.Nodes.getNodeAs<BinaryOperator>("myBind");
  assert(MatchedDecl);
  std::string Replace = std::string{clang::Lexer::getSourceText({MatchedDecl->getRHS()->getSourceRange(), true}, *Result.SourceManager, LangOpts)}
  + " "
  + MatchedDecl->getOpcodeStr().str()
  + " "
  + std::string{Lexer::getSourceText({MatchedDecl->getLHS()->getSourceRange(), true}, *Result.SourceManager, LangOpts)};
  diag(MatchedDecl->getBeginLoc(), "Binaryoperator %0 is not following the yoda coding style")
    << MatchedDecl->getSourceRange()
    << FixItHint::CreateReplacement({MatchedDecl->getBeginLoc(), MatchedDecl->getEndLoc()}, Replace);
  //diag(MatchedDecl->getBeginLoc(), "It is safer to place the constant to the left hand side in a condition", DiagnosticIDs::Note);
}

} // namespace clang::tidy::bugprone

