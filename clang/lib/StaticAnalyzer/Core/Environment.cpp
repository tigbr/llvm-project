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

SVal Environment::lookupExpr(const EnvironmentManager &EnvMgr, const EnvironmentEntry &E) const {
  unsigned LayerIndex = BottomLayerIndex;
  const LocationContext *Location = BottomLocation;
  while (Location && Location != E.second) {
    Location = Location->getParent();
    LayerIndex = EnvMgr.Layers[LayerIndex].ParentLayerIndex;
  }
  if (Location) {
    const SVal *result = EnvMgr.Layers[LayerIndex].ExprBindings.lookup(E.first);
    if (result)
      return *result;
  }
  return UnknownVal();
}

const LocationContext* Environment::getLocationContext() const {
  return BottomLocation;
}

SVal Environment::getSVal(const EnvironmentManager &EnvMgr, const EnvironmentEntry &Entry,
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
      return getSVal(EnvMgr, EnvironmentEntry(RE, LCtx), svalBuilder);
    return UndefinedVal();
  }

  // Handle all other Stmt* using a lookup.
  default:
    return lookupExpr(EnvMgr, EnvironmentEntry(S, LCtx));
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
  assert(Env->getLocationContext() && "Bad Environment construction!");
  assert(E.second && "Binding location must be provided!");

  if (V.isUnknown() && !Invalidate) {
    return *Env;
  }

  if (Env->getLocationContext() == E.second) {
    if (V.isUnknown()) {
      if (Invalidate) {
        Layer OldLayer{Layers[Env->BottomLayerIndex]};
        Layer NewLayer{BindingsFactory.remove(OldLayer.ExprBindings, E.first), OldLayer.ParentLayerIndex};
        return Environment(saveLayer(NewLayer), Env->getLocationContext());
      }
    }
    unsigned LayerIndex = Env->BottomLayerIndex;
    Layer OldLayer{Layers[LayerIndex]};
    Layer NewLayer{BindingsFactory.add(OldLayer.ExprBindings, E.first, V), OldLayer.ParentLayerIndex};
    return Environment(saveLayer(NewLayer), Env->getLocationContext());
  } else if (E.second->isParentOf(Env->getLocationContext())) {

    std::vector<Layer> NewLayers;
    unsigned LayerIndex = Env->BottomLayerIndex;
    const LocationContext *Location = Env->BottomLocation;
    do {
      NewLayers.push_back(Layers[LayerIndex]);
      LayerIndex = Layers[LayerIndex].ParentLayerIndex;
      Location = Location->getParent();
    } while (Location != E.second);

    Layer OldLayer{Layers[LayerIndex]};
    if (V.isUnknown()) {
      if (Invalidate) {
        NewLayers.push_back(Layer{BindingsFactory.remove(OldLayer.ExprBindings, E.first), OldLayer.ParentLayerIndex});
      }
    } else {
      NewLayers.push_back(Layer{BindingsFactory.add(OldLayer.ExprBindings, E.first, V), OldLayer.ParentLayerIndex});
    }

    for (int i = NewLayers.size() - 1; i > 0; i -= 1) {
      NewLayers[i-1].ParentLayerIndex = saveLayer(NewLayers[i]);
    }

    return Environment(saveLayer(NewLayers[0]), Env->getLocationContext());
  } else if (Env->getLocationContext() == E.second->getParent()) {
	Layer layer{BindingsFactory.add(BindingsFactory.getEmptyMap(), E.first, V), Env->BottomLayerIndex};
    return Environment(saveLayer(layer), E.second);
  } else {
    const LocationContext *Location1 = Env->getLocationContext();
    unsigned LayerIndex = Env->BottomLayerIndex;
    while (Location1) {
      if (Location1->isParentOf(E.second)) {
        std::vector<Layer> NewLayers{Layer{BindingsFactory.add(BindingsFactory.getEmptyMap(), E.first, V), Env->BottomLayerIndex}};

        const LocationContext *Location = E.second->getParent();
        while (Location != Location1) {
          NewLayers.push_back(Layer{BindingsFactory.getEmptyMap(), 0});
          Location = Location->getParent();
        }

        NewLayers.back().ParentLayerIndex = LayerIndex;
        for (int i = NewLayers.size() - 1; i > 0; i -= 1) {
          NewLayers[i-1].ParentLayerIndex = saveLayer(NewLayers[i]);
        }

        return Environment(saveLayer(NewLayers[0]), E.second);
      }
      LayerIndex = Layers[LayerIndex].ParentLayerIndex;
      Location1 = Location1->getParent();
    }

	assert(E.second->getParent() == nullptr && "Should be top level here!");
	unsigned id = saveLayer(Layer{BindingsFactory.add(BindingsFactory.getEmptyMap(), E.first, V)});
    Layers[id].ParentLayerIndex = id;
    return Environment(id, E.second);
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
  Layer BaseLayer = Layers[Env.BottomLayerIndex];
  const LocationContext *CurrentStackFrame = SymReaper.getLocationContext();
  const LocationContext *NewStackFrame = Env.getLocationContext();

  while (NewStackFrame && !NewStackFrame->inTopFrame() && CurrentStackFrame->isParentOf(NewStackFrame)) {
    NewStackFrame = NewStackFrame->getParent();
    BaseLayer = Layers[BaseLayer.ParentLayerIndex];
  }

  MarkLiveCallback CB(SymReaper);
  ScanReachableSymbols RSScaner(ST, CB);

  Layer OldLayer = BaseLayer;
  std::vector<Layer> NewLayers;
  for (const LocationContext *location = NewStackFrame; location; location = location->getParent(), OldLayer = Layers[OldLayer.ParentLayerIndex]) {
    NewLayers.push_back({BindingsFactory.getEmptyMap(), OldLayer.ParentLayerIndex});
    llvm::ImmutableMapRef<const Stmt*, SVal> EBMapRef(NewLayers.back().ExprBindings.getRootWithoutRetain(), BindingsFactory.getTreeFactory());
    for (auto it = OldLayer.ExprBindings.begin(); it != OldLayer.ExprBindings.end(); it++) {
      const Stmt *BlkExpr = it.getKey();
      SVal X = it.getData();

      const Expr *E = dyn_cast<Expr>(BlkExpr);
      if (E && SymReaper.isLive(E, location)) {
        // Keep the binding
        // Mark all symbols in the block expr's value live.
        RSScaner.scan(X);
        EBMapRef = EBMapRef.add(E, X);
      }
    }

    NewLayers.back().ExprBindings = EBMapRef.asImmutableMap();
  }

  for (int i = NewLayers.size() - 1; i > 0; i -= 1) {
    NewLayers[i-1].ParentLayerIndex = saveLayer(NewLayers[i]);
  }

  return Environment(saveLayer(NewLayers[0]), NewStackFrame);

#if 0
  Environment NewEnv = getInitialEnvironment(NewStackFrame);
  MarkLiveCallback CB(SymReaper);
  ScanReachableSymbols RSScaner(ST, CB);

  llvm::ImmutableMapRef<const Stmt*, SVal> EBMapRef(NewEnv.ExprBindings.getRootWithoutRetain(), BindingsFactory.getTreeFactory());

  // Iterate over the block-expr bindings.
  for (Environment::iterator I = Env.begin(), End = Env.end(); I != End; ++I) {
    const Stmt *BlkExpr = I->first;
    SVal X = I.getData();

    const Expr *E = dyn_cast<Expr>(BlkExpr);
    if (!E)
      continue;

    if (SymReaper.isLive(E, Env.getStackFrameContext())) {
      // Copy the binding to the new map.
      EBMapRef = EBMapRef.add(BlkExpr, X);

      // Mark all symbols in the block expr's value live.
      RSScaner.scan(X);
    }
  }

  NewEnv.ExprBindings = EBMapRef.asImmutableMap();
  return NewEnv;
#endif
}

void Environment::printJson(raw_ostream &Out, EnvironmentManager &EnvMgr, const ASTContext &Ctx,
                            const LocationContext *LCtx, const char *NL,
                            unsigned int Space, bool IsDot) const {
#if 0
  Indent(Out, Space, IsDot) << "\"environment\": ";

  Layer layer{EnvMgr.Layers[BottomLayerIndex]};
  const LocationContext *L = BottomLocation;
  bool hasNoBindings = true;
  while (L && hasNoBindings) {
    if (layer.ExprBindings.isEmpty()) {
      L = L->getParent();
      layer = EnvMgr.Layers[layer.ParentLayerIndex];
    } else {
      hasNoBindings = false;
    }
  }

  if (hasNoBindings) {
    Out << "null," << NL;
    return;
  }

  ++Space;
#if 0
  if (!LCtx) {
    // Find the freshest location context.
    llvm::SmallPtrSet<const LocationContext *, 16> FoundContexts;
    for (const auto &I : *this) {
      const LocationContext *LC = StackFrame;
      if (FoundContexts.count(LC) == 0) {
        // This context is fresher than all other contexts so far.
        LCtx = LC;
        for (const LocationContext *LCI = LC; LCI; LCI = LCI->getParent())
          FoundContexts.insert(LCI);
      }
    }
  }
#endif

  assert(LCtx);

  Out << "{ \"pointer\": \"" << (const void *)LCtx->getStackFrame()
      << "\", \"items\": [" << NL;
  PrintingPolicy PP = Ctx.getPrintingPolicy();

  LCtx->printJson(Out, NL, Space, IsDot, [&](const LocationContext *LC) {
    // LCtx items begin
    bool HasItem = false;
    unsigned int InnerSpace = Space + 1;

    // Store the last ExprBinding which we will print.
    Layer layer{EnvMgr.Layers[BottomLayerIndex]};
    const LocationContext *Location = BottomLocation;
    while (Location != LC) {
      layer = EnvMgr.Layers[layer.ParentLayerIndex];
      Location = Location->getParent();
      if (Location == nullptr) return;
    }
    auto &ExprBindings = layer.ExprBindings;
    using BindingsTy = llvm::ImmutableMap<const Stmt*, SVal>;
    BindingsTy::iterator LastI = ExprBindings.end();

#if 0
    for (BindingsTy::iterator I = ExprBindings.begin(); I != ExprBindings.end(); ++I) {
      if (StackFrame != LC)
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
#endif

    for (BindingsTy::iterator I = ExprBindings.begin(); I != ExprBindings.end(); ++I) {

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
