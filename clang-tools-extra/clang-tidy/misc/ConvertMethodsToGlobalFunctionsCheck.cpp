//===--- ConvertMethodsToGlobalFunctionsCheck.cpp - clang-tidy ------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "ConvertMethodsToGlobalFunctionsCheck.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Lex/Lexer.h"
#include "llvm/Support/raw_ostream.h"

using namespace clang::ast_matchers;

namespace clang::tidy::misc {

void ConvertMethodsToGlobalFunctionsCheck::registerMatchers(
    MatchFinder *Finder) {
  Finder->addMatcher(
      cxxMemberCallExpr(
          callee(cxxMethodDecl(hasAnyName("cbegin", "cend", "crbegin", "crend"),
                               isConst(), parameterCountIs(0))))
          .bind("root"),
      this);
  Finder->addMatcher(
      cxxMemberCallExpr(
          callee(cxxMethodDecl(hasAnyName("begin", "end", "rbegin", "rend"),
                               parameterCountIs(0))))
          .bind("root"),
      this);
  // Finder->addMatcher(cxxMemberCallExpr(callee(cxxMethodDecl(hasAnyName("swap"),parameterCountIs(1)))).bind("root"),
  // this);
  if (getLangOpts().CPlusPlus17)
    Finder->addMatcher(
        cxxMemberCallExpr(callee(cxxMethodDecl(hasAnyName("size", "empty"),
                                               isConst(), parameterCountIs(0))))
            .bind("root"),
        this);
}

bool ConvertMethodsToGlobalFunctionsCheck::isLanguageVersionSupported(
    const LangOptions &LangOpts) const {
  return LangOpts.CPlusPlus11;
}

void ConvertMethodsToGlobalFunctionsCheck::check(
    const MatchFinder::MatchResult &Result) {

  const auto *MemberCallExpr =
      Result.Nodes.getNodeAs<CXXMemberCallExpr>("root");
  const auto *MethodDecl =
      llvm::dyn_cast_or_null<CXXMethodDecl>(MemberCallExpr->getDirectCallee());
  const auto *ObjectDecl = MethodDecl->getParent();
  assert(MemberCallExpr && MethodDecl && ObjectDecl &&
         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

  // if (!ObjectDecl->isInStdNamespace()) return;

  SourceLocation begin{MemberCallExpr->getBeginLoc()};
  SourceLocation end{MemberCallExpr->getRParenLoc()};
  if (begin.isInvalid() || end.isInvalid() || begin.isMacroID() ||
      end.isMacroID())
    return;
  std::string fixit;
  clang::LangOptions lopt = getLangOpts();

  if (clang::Lexer::getSourceText({{begin, end}, true}, *Result.SourceManager,
                                  lopt) == ":")
    return;

  if (begin == MemberCallExpr->getExprLoc()) {
    fixit = "std::" + std::string{MethodDecl->getName().data()} + "(*this";
    for (size_t i = 0; i < MemberCallExpr->getNumArgs(); i++) {
      fixit += ", ";
      fixit += clang::Lexer::getSourceText(
          {MemberCallExpr->getArg(i)->getSourceRange(), true},
          *Result.SourceManager, lopt);
    }
    fixit += ")";
  } else {
    SourceLocation currentLocation;
    SourceLocation tokenLocation = begin;
    std::optional<Token> prevtoken;
    std::optional<Token> token;
    do {
      currentLocation = tokenLocation;
      prevtoken = token;
      token = clang::Lexer::findNextToken(currentLocation,
                                          *Result.SourceManager, lopt);
      tokenLocation = token->getLocation();
    } while (tokenLocation != MemberCallExpr->getExprLoc());
    CharSourceRange sourceRange{{begin, prevtoken->getLocation()}, true};
    StringRef textUntilDot =
        clang::Lexer::getSourceText(sourceRange, *Result.SourceManager, lopt);
    std::string tokenAsString =
        clang::Lexer::getSpelling(*prevtoken, *Result.SourceManager, lopt);

    if (!(tokenAsString == "->" || tokenAsString == "."))
      return;
    fixit = "std::" + std::string{MethodDecl->getName().data()} +
            std::string{"("} +
            (tokenAsString == "->" ? std::string{"*"} : std::string{""}) +
            std::string{textUntilDot.drop_back(prevtoken->getLength())};
    for (size_t i = 0; i < MemberCallExpr->getNumArgs(); i++) {
      fixit += ", ";
      fixit += clang::Lexer::getSourceText(
          {MemberCallExpr->getArg(i)->getSourceRange(), true},
          *Result.SourceManager, lopt);
    }
    fixit += ")";
  }

  diag(MemberCallExpr->getRParenLoc(), "is not using the global version")
      << FixItHint::CreateReplacement(
             {MemberCallExpr->getBeginLoc(), MemberCallExpr->getRParenLoc()},
             fixit);
}

} // namespace clang::tidy::misc
