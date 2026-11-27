//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "AlwaysDereferencedVariableCheck.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"

using namespace clang::ast_matchers;

namespace clang::tidy::readability {

#define BN(Name) static const StringRef Name = #Name;
BN(UnaryOperatorBindName);
BN(ArraySubscriptExprBindName);
BN(PtrVariableDeclBindName);
BN(StdOptionalVariableDeclBindName);
BN(ArrowMemberExprBindName);
BN(FunctionPtrCallBindName);
BN(StdOptionalCallToMethodValueBindName);
BN(StdOptionalCallToStarOperatorBindName);
BN(StdOptionalArrowOperatorBindName);
#undef BN

void AlwaysDereferencedVariableCheck::registerMatchers(MatchFinder *Finder) {
  Finder->addMatcher(translationUnitDecl(), this);
}

struct DeclStatistic {
  unsigned UsageCount;
  unsigned DereferenceCount;
};

struct PointersCallback
    : public clang::ast_matchers::MatchFinder::MatchCallback {
  std::map<const Decl *, DeclStatistic> DeclStats;

  void run(const MatchFinder::MatchResult &Result) override {
    const Decl *D = Result.Nodes.getNodeAs<Decl>(PtrVariableDeclBindName);

    const UnaryOperator *UO =
        Result.Nodes.getNodeAs<UnaryOperator>(UnaryOperatorBindName);
    if (UO && UO->getOpcode() == UO_Deref) {
      DeclStats[D].DereferenceCount += 1;
      return;
    }

    const ArraySubscriptExpr *ASE =
        Result.Nodes.getNodeAs<ArraySubscriptExpr>(ArraySubscriptExprBindName);
    if (ASE) {
      DeclStats[D].DereferenceCount += 1;
      return;
    }

    const MemberExpr *ME =
        Result.Nodes.getNodeAs<MemberExpr>(ArrowMemberExprBindName);
    if (ME) {
      DeclStats[D].DereferenceCount += 1;
      return;
    }

    const CallExpr *CE =
        Result.Nodes.getNodeAs<CallExpr>(FunctionPtrCallBindName);
    if (CE) {
      DeclStats[D].DereferenceCount += 1;
      return;
    }

    DeclStats[D].UsageCount += 1;
  }
};

struct StdOptionalsCallback
    : public clang::ast_matchers::MatchFinder::MatchCallback {
  std::map<const Decl *, DeclStatistic> DeclStats;

  void run(const MatchFinder::MatchResult &Result) override {
    const Decl *D =
        Result.Nodes.getNodeAs<Decl>(StdOptionalVariableDeclBindName);

    const CXXMemberCallExpr *MC = Result.Nodes.getNodeAs<CXXMemberCallExpr>(
        StdOptionalCallToMethodValueBindName);
    if (MC) {
      DeclStats[D].DereferenceCount += 1;
      return;
    }

    const CXXOperatorCallExpr *OC = Result.Nodes.getNodeAs<CXXOperatorCallExpr>(
        StdOptionalCallToStarOperatorBindName);
    if (OC) {
      DeclStats[D].DereferenceCount += 1;
      return;
    }

    const MemberExpr *ME =
        Result.Nodes.getNodeAs<MemberExpr>(StdOptionalArrowOperatorBindName);
    if (ME) {
      DeclStats[D].DereferenceCount += 1;
      return;
    }

    DeclStats[D].UsageCount += 1;
  }
};

void AlwaysDereferencedVariableCheck::check(
    const MatchFinder::MatchResult &Result) {
  clang::ast_matchers::MatchFinder Finder;
  auto IPC = ignoringParenCasts;

  PointersCallback CBP;
  auto declRefToPtrVar = declRefExpr(hasDeclaration(
      parmVarDecl(hasType(pointerType())).bind(PtrVariableDeclBindName)));
  Finder.addMatcher(declRefToPtrVar, &CBP);
  Finder.addMatcher(unaryOperator(hasUnaryOperand(IPC(declRefToPtrVar)))
                        .bind(UnaryOperatorBindName),
                    &CBP);
  Finder.addMatcher(
      arraySubscriptExpr(
          anyOf(allOf(hasLHS(IPC(declRefToPtrVar)),
                      hasRHS(ignoringParenCasts(integerLiteral(equals(0))))),
                allOf(hasLHS(ignoringParenCasts(integerLiteral(equals(0)))),
                      hasRHS(IPC(declRefToPtrVar)))))
          .bind(ArraySubscriptExprBindName),
      &CBP);
  Finder.addMatcher(
      memberExpr(isArrow(), hasObjectExpression(IPC(declRefToPtrVar)))
          .bind(ArrowMemberExprBindName),
      &CBP);
  Finder.addMatcher(callExpr(callee(expr(IPC(declRefToPtrVar))))
                        .bind(FunctionPtrCallBindName),
                    &CBP);

  StdOptionalsCallback CBSO;
  auto StdOptionalVariable =
      parmVarDecl(hasType(qualType(hasCanonicalType(recordType(hasDeclaration(
                      recordDecl(hasName("optional"), isInStdNamespace())))))))
          .bind(StdOptionalVariableDeclBindName);
  auto declRefToStdOptional = declRefExpr(hasDeclaration(StdOptionalVariable));
  Finder.addMatcher(declRefToStdOptional, &CBSO);
  Finder.addMatcher(cxxMemberCallExpr(on(IPC(declRefToStdOptional)),
                                      callee(cxxMethodDecl(hasName("value"))))
                        .bind(StdOptionalCallToMethodValueBindName),
                    &CBSO);
  Finder.addMatcher(
      cxxOperatorCallExpr(hasUnaryOperand(IPC(declRefToStdOptional)),
                          hasOverloadedOperatorName("*"))
          .bind(StdOptionalCallToStarOperatorBindName),
      &CBSO);
  Finder.addMatcher(
      memberExpr(isArrow(), hasObjectExpression(cxxOperatorCallExpr(
                                hasUnaryOperand(IPC(declRefToStdOptional)))))
          .bind(StdOptionalArrowOperatorBindName),
      &CBSO);

  Finder.matchAST(*Result.Context);

  for (auto &[D, Stats] : CBP.DeclStats)
    if (Stats.UsageCount == Stats.DereferenceCount)
      diag(D->getLocation(), "pointer is always dereferenced, consider "
                             "changing it to a reference");

  for (auto &[D, Stats] : CBSO.DeclStats)
    if (Stats.UsageCount == Stats.DereferenceCount)
      diag(D->getLocation(), "this std::optional is always dereferenced, "
                             "consider using the underlying type directly");
}

} // namespace clang::tidy::readability
