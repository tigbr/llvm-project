//===- Environment.cpp - Map from Stmt* to Locations/Values ---------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
//  This file defined the Environment and EnvironmentManager classes.
//
//===----------------------------------------------------------------------===//

#include "clang/StaticAnalyzer/Core/PathSensitive/Environment.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ExprCXX.h"
#include "clang/AST/PrettyPrinter.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/StmtObjC.h"
#include "clang/Analysis/AnalysisDeclContext.h"
#include "clang/Basic/JsonSupport.h"
#include "clang/Basic/LLVM.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SValBuilder.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SVals.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymExpr.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymbolManager.h"
#include "llvm/ADT/ImmutableMap.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"
#include <cassert>

using namespace clang;
using namespace ento;

static const Expr *ignoreTransparentExprs(const Expr *E) {
  E = E->IgnoreParens();

  switch (E->getStmtClass()) {
  case Stmt::OpaqueValueExprClass:
    if (const Expr *SE = cast<OpaqueValueExpr>(E)->getSourceExpr()) {
      E = SE;
      break;
    }
    return E;
  case Stmt::ExprWithCleanupsClass:
    E = cast<ExprWithCleanups>(E)->getSubExpr();
    break;
  case Stmt::ConstantExprClass:
    E = cast<ConstantExpr>(E)->getSubExpr();
    break;
  case Stmt::CXXBindTemporaryExprClass:
    E = cast<CXXBindTemporaryExpr>(E)->getSubExpr();
    break;
  case Stmt::SubstNonTypeTemplateParmExprClass:
    E = cast<SubstNonTypeTemplateParmExpr>(E)->getReplacement();
    break;
  default:
    // This is the base case: we can't look through more than we already have.
    return E;
  }

  return ignoreTransparentExprs(E);
}

static const Stmt *ignoreTransparentExprs(const Stmt *S) {
  if (const auto *E = dyn_cast<Expr>(S))
    return ignoreTransparentExprs(E);
  return S;
}

EnvironmentEntry::EnvironmentEntry(const Stmt *S, const LocationContext *L)
    : std::pair<const Stmt *,
                const StackFrameContext *>(ignoreTransparentExprs(S),
                                           L ? L->getStackFrame()
                                             : nullptr) {}

SVal Environment::lookupExpr(const EnvironmentEntry &E) const {
  const Environment *ES = this;
  while (ES->Parent && E.second->isParentOf(ES->Location)) {
    ES = ES->Parent;
  }
  const SVal* X = ES->ExprBindings.lookup(E.first);
  if (X) {
    SVal V = *X;
    return V;
  }
  return UnknownVal();
}

const Environment* Environment::getParent() const {
  return Parent;
}

const LocationContext* Environment::getLocationContext() const {
  return Location;
}

SVal Environment::getSVal(const EnvironmentEntry &Entry,
                          SValBuilder& svalBuilder) const {
  const Stmt *S = Entry.getStmt();
  assert(!isa<ObjCForCollectionStmt>(S) &&
         "Use ExprEngine::hasMoreIteration()!");
  assert((isa<Expr, ReturnStmt>(S)) &&
         "Environment can only argue about Exprs, since only they express "
         "a value! Any non-expression statement stored in Environment is a "
         "result of a hack!");
  const LocationContext *LCtx = Entry.getLocationContext();

  switch (S->getStmtClass()) {
  case Stmt::CXXBindTemporaryExprClass:
  case Stmt::ExprWithCleanupsClass:
  case Stmt::GenericSelectionExprClass:
  case Stmt::ConstantExprClass:
  case Stmt::ParenExprClass:
  case Stmt::SubstNonTypeTemplateParmExprClass:
    llvm_unreachable("Should have been handled by ignoreTransparentExprs");

  case Stmt::AddrLabelExprClass:
  case Stmt::CharacterLiteralClass:
  case Stmt::CXXBoolLiteralExprClass:
  case Stmt::CXXScalarValueInitExprClass:
  case Stmt::ImplicitValueInitExprClass:
  case Stmt::IntegerLiteralClass:
  case Stmt::ObjCBoolLiteralExprClass:
  case Stmt::CXXNullPtrLiteralExprClass:
  case Stmt::ObjCStringLiteralClass:
  case Stmt::StringLiteralClass:
  case Stmt::TypeTraitExprClass:
  case Stmt::SizeOfPackExprClass:
  case Stmt::PredefinedExprClass:
    // Known constants; defer to SValBuilder.
    return *svalBuilder.getConstantVal(cast<Expr>(S));

  case Stmt::ReturnStmtClass: {
    const auto *RS = cast<ReturnStmt>(S);
    if (const Expr *RE = RS->getRetValue())
      return getSVal(EnvironmentEntry(RE, LCtx), svalBuilder);
    return UndefinedVal();
  }

  // Handle all other Stmt* using a lookup.
  default:
    return lookupExpr(EnvironmentEntry(S, LCtx));
  }
}

// TODO_: What if the EnvironmentEntry's StackFrameContext is different from
// the one in the Environment?
// After one quick grep, bindExpr seems to be used by ProgramState.cpp in
// the BindExpr (with capital B) method.
Environment EnvironmentManager::bindExpr(const Environment *Env,
                                         const EnvironmentEntry &E,
                                         SVal V,
                                         bool Invalidate) {
  // assert(!(Env->getLocationContext() && E.second->isParentOf(Env->getLocationContext())));
  // TODO_: Assuming that the StackFrameContext of E is the same as
  // Env's StackFrameContext or perhaps its immediate descendant
  // const Environment *Parent = Env->Parent;
  // if (Env->getLocationContext() && Env->getLocationContext()->isParentOf(E.second))
  //   Parent = Env;
    
  if (V.isUnknown()) {
    if (Invalidate)
      return Environment(Env->Parent, Env->getLocationContext(), F.remove(Env->ExprBindings, E.first));
    else
      return *Env;
  }
  if (Env->getLocationContext() == E.second || E.second->isParentOf(Env->getLocationContext())) {
    return Environment(Env->Parent, Env->getLocationContext(), F.add(Env->ExprBindings, E.first, V));
  } else {
    return Environment(Env, E.second, F.add(F.getEmptyMap(), E.first, V));
  }
}

namespace {

class MarkLiveCallback final : public SymbolVisitor {
  SymbolReaper &SymReaper;

public:
  MarkLiveCallback(SymbolReaper &symreaper) : SymReaper(symreaper) {}

  bool VisitSymbol(SymbolRef sym) override {
    SymReaper.markLive(sym);
    return true;
  }

  bool VisitMemRegion(const MemRegion *R) override {
    SymReaper.markLive(R);
    return true;
  }
};

} // namespace

// removeDeadBindings:
//  - Remove subexpression bindings.
//  - Remove dead block expression bindings.
//  - Keep live block expression bindings:
//   - Mark their reachable symbols live in SymbolReaper,
//     see ScanReachableSymbols.
//   - Mark the region in DRoots if the binding is a loc::MemRegionVal.
Environment
EnvironmentManager::removeDeadBindings(Environment Env,
                                       SymbolReaper &SymReaper,
                                       ProgramStateRef ST) {
  // TODO_: What if this returns null?
  const LocationContext *CurrentStackFrame = SymReaper.getLocationContext();
  const LocationContext *NewStackFrame = Env.getLocationContext();
  const Environment *NewParent = Env.getParent();

  while (NewStackFrame && !NewStackFrame->inTopFrame() && CurrentStackFrame->isParentOf(NewStackFrame)) {
    NewStackFrame = NewStackFrame->getParent();
    NewParent = NewParent->getParent();
  }

  Environment NewEnv = getInitialEnvironment(NewParent, NewStackFrame);
  MarkLiveCallback CB(SymReaper);
  ScanReachableSymbols RSScaner(ST, CB);

  llvm::ImmutableMapRef<const Stmt*, SVal>
    EBMapRef(NewEnv.ExprBindings.getRootWithoutRetain(),
             F.getTreeFactory());

  // Iterate over the block-expr bindings.
  // for (const Environment *CurrentEnv = &Env; CurrentEnv && NewParent != CurrentEnv->getParent(); CurrentEnv = CurrentEnv->getParent()) {
    for (Environment::iterator I = Env.begin(), End = Env.end(); I != End; ++I) {
      const Stmt *BlkExpr = I->first;
      SVal X = I.getData();

      const Expr *E = dyn_cast<Expr>(BlkExpr);
      if (!E)
        continue;

      if (SymReaper.isLive(E, Env.getLocationContext())) {
        // Copy the binding to the new map.
        EBMapRef = EBMapRef.add(BlkExpr, X);

        // Mark all symbols in the block expr's value live.
        RSScaner.scan(X);
      }
    }
  // }

  NewEnv.ExprBindings = EBMapRef.asImmutableMap();
  return NewEnv;
}

void Environment::printJson(raw_ostream &Out, const ASTContext &Ctx,
                            const LocationContext *LCtx, const char *NL,
                            unsigned int Space, bool IsDot) const {
#if 1
  Indent(Out, Space, IsDot) << "\"environment\": ";

  if (ExprBindings.isEmpty()) {
    Out << "null," << NL;
    return;
  }

  ++Space;
  if (!LCtx) {
    // Find the freshest location context.
    llvm::SmallPtrSet<const LocationContext *, 16> FoundContexts;
    for (const auto &I : *this) {
      const LocationContext *LC = this->Location;
      if (FoundContexts.count(LC) == 0) {
        // This context is fresher than all other contexts so far.
        LCtx = LC;
        for (const LocationContext *LCI = LC; LCI; LCI = LCI->getParent())
          FoundContexts.insert(LCI);
      }
    }
  }

  assert(LCtx);

  Out << "{ \"pointer\": \"" << (const void *)LCtx->getStackFrame()
      << "\", \"items\": [" << NL;
  PrintingPolicy PP = Ctx.getPrintingPolicy();

  LCtx->printJson(Out, NL, Space, IsDot, [&](const LocationContext *LC) {
    // LCtx items begin
    bool HasItem = false;
    unsigned int InnerSpace = Space + 1;

    // Store the last ExprBinding which we will print.
    BindingsTy::iterator LastI = ExprBindings.end();
    for (BindingsTy::iterator I = ExprBindings.begin(); I != ExprBindings.end();
         ++I) {
      if (this->Location != LC)
        continue;

      if (!HasItem) {
        HasItem = true;
        Out << '[' << NL;
      }

      const Stmt *S = I->first;
      (void)S;
      assert(S != nullptr && "Expected non-null Stmt");

      LastI = I;
    }

    for (BindingsTy::iterator I = ExprBindings.begin(); I != ExprBindings.end();
         ++I) {
      if (this->Location != LC)
        continue;

      const Stmt *S = I->first;
      Indent(Out, InnerSpace, IsDot)
          << "{ \"stmt_id\": " << S->getID(Ctx) << ", \"kind\": \""
          << S->getStmtClassName() << "\", \"pretty\": ";
      S->printJson(Out, nullptr, PP, /*AddQuotes=*/true);

      Out << ", \"value\": ";
      I->second.printJson(Out, /*AddQuotes=*/true);

      Out << " }";

      if (I != LastI)
        Out << ',';
      Out << NL;
    }

    if (HasItem)
      Indent(Out, --InnerSpace, IsDot) << ']';
    else
      Out << "null ";
  });

  Indent(Out, --Space, IsDot) << "]}," << NL;
#endif
}
