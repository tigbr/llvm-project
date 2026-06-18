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

EnvironmentEntry::EnvironmentEntry(const Expr *E, const StackFrame *SF)
    : std::pair<const Expr *, const StackFrame *>(ignoreTransparentExprs(E),
                                                  SF) {}

SVal Environment::lookupExpr(const EnvironmentEntry &Entry) const {
  const Layer *L = BottomLayer;
  const StackFrame *SF = BottomStackFrame;
  while (SF && SF != Entry.second) {
    SF = SF->getParent();
    L = L->Parent;
  }
  if (L)
    if (const SVal *Result = L->Bindings.lookup(Entry.first))
      return *Result;
  return UnknownVal();
}

SVal Environment::getSVal(const EnvironmentEntry &Entry,
                          SValBuilder& svalBuilder) const {
  static unsigned call_id = 0;
  call_id += 1;
  const Expr *Ex = Entry.getExpr();
  const StackFrame *SF = Entry.getStackFrame();

  switch (Ex->getStmtClass()) {
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
    return *svalBuilder.getConstantVal(Ex);

  // Handle all other Expr* using a lookup.
  default:
    return lookupExpr(EnvironmentEntry(Ex, SF));
  }
}

int sfLevel(const StackFrame *SF) {
  int Res = 0;
  while (SF) {
    Res++;
    SF = SF->getParent();
  }
  return Res;
}

const StackFrame* sfNthParent(const StackFrame *SF, int N) {
  while (N-- > 0)
    SF = SF->getParent();
  return SF;
}

Environment EnvironmentManager::bindExpr(const Environment Env,
                                         const EnvironmentEntry &Entry,
                                         SVal V,
                                         bool Invalidate) {
  static unsigned call_id = 0;
  call_id += 1;

  if (V.isUnknown() && !Invalidate) {
    return Env;
  }

  // TODO remove "in this case"
  // In this case the binding specified by the EnvironmentEntry
  // should be removed from the layer where it appears.
  // Since a pointer to a Layer is expected to encode its ancestors too
  // (to make sure that the equality of Layer), a
  // modified Layer needs to have its descendants rebuilt (only the 
  // parent pointers have to be changed, their bindings are kept the same).

  // The case where Env.BottomStackFrame is a descendant of or equal to Entry.second.
  int StepsToRootFromEnvSF = 0;
  const Layer *L = Env.BottomLayer;
  const StackFrame *SF = Env.BottomStackFrame;
  std::vector<const Layer*> LayersToRebuild;
  while (SF) {
    assert(L && "Stack frames and layers must be in sync");
    if (SF == Entry.second) {
      if (V.isUnknown() && Invalidate) {
        L = makeLayer(L->Parent, F.remove(L->Bindings, Entry.first));
        while (!LayersToRebuild.empty()) {
          L = makeLayer(L, LayersToRebuild.back()->Bindings);
          LayersToRebuild.pop_back();
        }
        // Remove consecutive empty layers from bottom
        SF = Env.BottomStackFrame;
        while (SF->getParent() && L->isEmpty()) {
          SF = SF->getParent();
          L = L->Parent;
        }
        return Environment(SF, L).validateInvariants(Entry, V, Invalidate);
      } else {
        L = makeLayer(L->Parent, F.add(L->Bindings, Entry.first, V));
        while (!LayersToRebuild.empty()) {
          L = makeLayer(L, LayersToRebuild.back()->Bindings);
          LayersToRebuild.pop_back();
        }
        return Environment(Env.BottomStackFrame, L).validateInvariants(Entry, V, Invalidate);
      }
    }
    LayersToRebuild.push_back(L);
    L = L->Parent;
    SF = SF->getParent();
  }

  // The case where Entry.second is a descendant of Env.BottomStackFrame (and
  // not equal to Env.BottomStackFrame, because that case was already handled).
  int StepsToRootFromEntrySF = 0;
  int StepsToEnvSF = 0;
  L = Env.BottomLayer;
  SF = Entry.second;
  LayersToRebuild.clear();
  while (SF) {
    if (SF == Env.BottomStackFrame) {
      while (1 < StepsToEnvSF) {
        L = makeLayer(L, F.getEmptyMap());
        StepsToEnvSF -= 1;
      }
      return Environment(Entry.second, makeLayer(L, F.add(F.getEmptyMap(), Entry.first, V))).validateInvariants(Entry, V, Invalidate);
    }
    StepsToEnvSF += 1;
    StepsToRootFromEntrySF += 1;
    SF = SF->getParent();
  }
  assert(false && "bindExpr not in an ancestor or descendant stack frame");
#if 0

  // The case where Entry.second and Env.BottomStackFrame are siblings.
  // Leveled means that they are the same distance away from root.
  int Diff = StepsToRootFromEntrySF - StepsToRootFromEnvSF;
  const StackFrame *LeveledEntrySF = sfNthParent(Entry.second, Diff);
  const StackFrame *LeveledEnvSF = sfNthParent(Env.BottomStackFrame, -Diff);

  int StepsFromLeveledToCommonAncestor = 0;
  const StackFrame *CommonAncestorEntrySF = LeveledEntrySF;
  const StackFrame *CommonAncestorEnvSF = LeveledEnvSF;
  while (CommonAncestorEntrySF != CommonAncestorEnvSF) {
    CommonAncestorEntrySF = CommonAncestorEntrySF->getParent();
    CommonAncestorEnvSF = CommonAncestorEnvSF->getParent();
    StepsFromLeveledToCommonAncestor += 1;
  }
  const StackFrame *CommonAncestor = CommonAncestorEntrySF;

  int StepsFromEntrySFToCommonAncestor = StepsFromLeveledToCommonAncestor + Diff;

  L = Env.BottomLayer;
  for (int i = 0; i < (-Diff + StepsFromLeveledToCommonAncestor); i += 1) {
    L = L->Parent;
  }

  while (1 < StepsFromEntrySFToCommonAncestor) {
    L = makeLayer(L, F.getEmptyMap());
    StepsFromEntrySFToCommonAncestor -= 1;
  }
  if (V.isUnknown() && Invalidate) {
     L = makeLayer(L->Parent, F.remove(L->Bindings, Entry.first));
     while (!LayersToRebuild.empty()) {
       L = makeLayer(L, LayersToRebuild.back()->Bindings);
       LayersToRebuild.pop_back();
     }
     // Remove consecutive empty layers from bottom
     SF = Env.BottomStackFrame;
     while (SF->getParent() && nullptr == L->Bindings.getMaxElement()) {
       SF = SF->getParent();
       L = L->Parent;
     }
     return Environment(SF, L).validateInvariants();
  } else {
    L = makeLayer(L, F.add(F.getEmptyMap(), Entry.first, V));
    return Environment(Entry.second, L).validateInvariants();
  }

  assert(false && "nemar");

  // assert(0 && "The two StackFrames are not in the same hierarchy!");
  // return Env;
// IF 0 was here previously
  // We need to find the nearest common ancestor of the StackFrame in the
  // current Environment and the StackFrame contained in the EnvironmentEntry.
  // A common ancestor should exist, because of the analysis entry point.
  //
  // Both StackFrames are going to be walked upwards the chain of calls but
  // first we make sure that they are the same distance from the root call.
  int LevelDiff = sfLevel(Env.BottomStackFrame) - sfLevel(Entry.second);
  const StackFrame *CommonSFEnv = sfNthParent(Env.BottomStackFrame, LevelDiff);
  const StackFrame *CommonSFEE = sfNthParent(Entry.second, -LevelDiff);
  // int ExtraLevels = 0;
  while (CommonSFEnv != CommonSFEE) {
    // ExtraLevels += 1;
    CommonSFEnv = CommonSFEnv->getParent();
    CommonSFEE = CommonSFEE->getParent();
    assert(CommonSFEnv && CommonSFEE);
  }
  const StackFrame *CommonAncestorSF = CommonSFEnv;

  int TakeLayers = std::max(LevelDiff, 0); // + ExtraLevels;
  int AddLayers = std::max(-LevelDiff, 0); // + ExtraLevels;
  assert((TakeLayers == 0 || AddLayers == 0) && "We either take or add levels, but not both!");
  const Environment CommonEnv = Env;
  const Layer *CommonLayer = Env.BottomLayer;
  std::vector<const StackFrame*> TakenSFs;
  std::vector<llvm::ImmutableMap<const Expr*, SVal>> TakenMappings;
  while (TakeLayers--) {
    TakenSFs.push_back(CommonEnv.BottomStackFrame);
    TakenMappings.push_back(Layer->Bindings);
    CommonEnv = CommonEnv.getParent();
  }

  std::vector<const StackFrame*> EESFS(AddLayers);
  const StackFrame *Tmp = EESF;
  for (int I = 0; I < AddLayers; I++) {
    EESFS[I] = Tmp;
    Tmp = Tmp->getParent();
  }

  while (AddLayers--) {
    if (AddLayers == 0) {
      llvm::ImmutableMap<const Expr *, SVal> NewMapping = BindingsFactory.add(BindingsFactory.getEmptyMap(), E.first, V);
      return makeEnvironment(CommonEnv, EESFS[AddLayers], NewMapping);
    }
    CommonEnv = makeEnvironment(CommonEnv, EESFS[AddLayers], BindingsFactory.getEmptyMap());
  }
  // Here AddLayers was 0 and TakeLayers may have been > 0
  llvm::ImmutableMap<const Expr *, SVal> NewMapping = BindingsFactory.add(CommonEnv.Bindings, E.first, V);
  Environment ModifiedEnv = makeEnvironment(CommonEnv.getParent(), CommonEnv.BottomStackFrame, NewMapping);
  while (!TakenSFs.empty()) {
    ModifiedEnv = makeEnvironment(ModifiedEnv, TakenSFs.pop_back(), TakenMappings.pop_back());
  }
  return ModifiedEnv;
#endif
}

#if 0
Environment EnvironmentManager::bindExpr(Environment Env,
                                         const EnvironmentEntry &E,
                                         SVal V,
                                         bool Invalidate) {
  if (V.isUnknown()) {
    if (Invalidate)
      return Environment(F.remove(Env.ExprBindings, E));
    else
      return Env;
  }
  return Environment(F.add(Env.ExprBindings, E, V));
}
#endif

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

const Layer* EnvironmentManager::makeLayer(const Layer *P, Environment::BindingsTy B) {
  llvm::FoldingSetNodeID ID;
  Layer::Profile(ID, P, B);
  void *InsertPos;
  Layer *Result = Layers.FindNodeOrInsertPos(ID, InsertPos);
  if (Result)
    return Result;
  Result = new Layer(P, B);  // TODO use proper allocator
  Layers.InsertNode(Result, InsertPos);
  return Result;
}

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
  const Layer *L = Env.BottomLayer;
  const StackFrame *NewBottomStackFrame = nullptr;
  const StackFrame *SF = SymReaper.getStackFrame();

  bool foundBottomStackFrame = false;
  while (SF) {
    if (SF == Env.BottomStackFrame) {
      NewBottomStackFrame = Env.BottomStackFrame;
      foundBottomStackFrame = true;
      break;
    }
    SF = SF->getParent();
  }

  if (!foundBottomStackFrame) {
    SF = Env.BottomStackFrame;
    while (!SF->inTopFrame() && SF != SymReaper.getStackFrame()) {
      SF = SF->getParent();
      L = L->Parent;
    }
    NewBottomStackFrame = SF;
  }

  MarkLiveCallback CB(SymReaper);
  ScanReachableSymbols RSScaner(ST, CB);

  std::vector<std::pair<const Layer*, const StackFrame *>> NewLayers{{L, SF}};
  while (SF->getParent()) {
    SF = SF->getParent();
    L = L->Parent;
    NewLayers.push_back({L, SF});
  }

  bool isFirstLayerToBeRemade = true;
  while (!NewLayers.empty()) {
    llvm::ImmutableMap<const Expr*, SVal> EmptyMap = F.getEmptyMap();
    llvm::ImmutableMapRef<const Expr*, SVal> EBMapRef(EmptyMap.getRootWithoutRetain(), F.getTreeFactory());
    assert(NewLayers.back().first && "Layer should not be null here!");
    for (auto it = NewLayers.back().first->Bindings.begin(); it != NewLayers.back().first->Bindings.end(); it++) {
      const Expr *E = it.getKey();
      SVal X = it.getData();

      if (E && SymReaper.isLive(E, NewLayers.back().second)) {
        // Copy the binding to the new map.
        EBMapRef = EBMapRef.add(E, X);

        // Mark all symbols in the block expr's value live.
        RSScaner.scan(X);
      }
    }
    L = makeLayer(isFirstLayerToBeRemade ? L->Parent : L, EBMapRef.asImmutableMap());
    isFirstLayerToBeRemade = false;
    NewLayers.pop_back();
  }

  while (!NewBottomStackFrame->inTopFrame() && L->isEmpty()) {
    NewBottomStackFrame = NewBottomStackFrame->getParent();
    L = L->Parent;
  }

  return Environment(NewBottomStackFrame, L).validateInvariants();
 
#if 0
  while (SF) {
    llvm::ImmutableMapRef<const Expr*, SVal> EBMapRef(F.getEmptyMap(), F.getTreeFactory());
    for (auto it = L->Bindings.begin(); it != L->Bindings.end(); it++) {
      const Expr *E = it.getKey();
      SVal X = it.getData();

      if (E && SymReaper.isLive(E, SF)) {
        // Keep the binding
        // Mark all symbols in the block expr's value live.
        RSScaner.scan(X);
        EBMapRef = EBMapRef.add(E, X);
      }
    }

    SF = SF->getParent();
    L = L->Parent;
    NewLayers.back().Bindings = EBMapRef.asImmutableMap();
  }

  const Layer *L = NewLayers.back();
  for (int i = NewLayers.size() - 1; i > 0; i -= 1) {
    NewLayers[i-1].Parent = makeLayer(NewLayers[i].Parent, NewLayers[i].Bindings);
  }

  return Environment(NewBottomStackFrame, makeLayer(NewLayers[0].Parent, NewLayers[0].Bindings)).validateInvariants();
#endif

#if 0
  // Iterate over the block-expr bindings.
  for (Environment::iterator I = Env.begin(), End = Env.end(); I != End; ++I) {
    const EnvironmentEntry &BlkExpr = I.getKey();
    SVal X = I.getData();

    if (SymReaper.isLive(BlkExpr.getExpr(), BlkExpr.getStackFrame())) {
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

void Environment::iterator::validateInvariants() const {
  
}

Environment Environment::validateInvariants(const EnvironmentEntry &Entry, SVal V, bool Invalidate) const {
  if (!(V.isUnknown() && Invalidate)) {
    assert(V == lookupExpr(Entry) && "The SVal must be added properly!");
  }
  if (V.isUnknown() && Invalidate) {
    assert(UnknownVal() == lookupExpr(Entry) && "The SVal must be added properly!");
  }
  return validateInvariants();
}

Environment Environment::validateInvariants() const {
  // StackFrame and Layer hierarchy is in sync
  const Layer *L = BottomLayer; 
  const StackFrame *SF = BottomStackFrame;
  while (SF) {
    if ((SF == nullptr && L != nullptr) || (SF != nullptr && L == nullptr)) {
      assert(false && "StackFrame and Layer hierarchies are out of sync!");
    }
    SF = SF->getParent();
    L = L->Parent;
  }

  if (BottomLayer->isEmpty() && !BottomStackFrame->inTopFrame()) {
    assert(false && "Empty bottom Layers appeared in non-top frame!");
  }

  return *this;
}

void Environment::printJson(raw_ostream &Out, const ASTContext &Ctx,
                            const StackFrame *SF, const char *NL,
                            unsigned int Space, bool IsDot) const {
  Indent(Out, Space, IsDot) << "\"environment\": ";

  if (BottomLayer->Bindings.isEmpty()) {
    Out << "null," << NL;
    return;
  }

  ++Space;
  if (!SF) {
    // Find the freshest stack frame.
#if 1
    // In the new representation the freshest stack frame: BottomStackFrame
    // is stored explicitly in the environment.
    SF = BottomStackFrame;
#else
    llvm::SmallPtrSet<const StackFrame *, 16> FoundStackFrames;
    for (const auto &I : *this) {
      const StackFrame *CurrentSF = I.first.getStackFrame();
      if (FoundStackFrames.count(CurrentSF) == 0) {
        // This stack frame is fresher than all other stack frames so far.
        SF = CurrentSF;
        for (const StackFrame *SFI = CurrentSF; SFI; SFI = SFI->getParent())
          FoundStackFrames.insert(SFI);
      }
    }
#endif
  }

  assert(SF);

  Out << "{ \"pointer\": \"" << (const void *)SF << "\", \"items\": [" << NL;
  PrintingPolicy PP = Ctx.getPrintingPolicy();

  const StackFrame *CurrentStackFrame = BottomStackFrame;
  const Layer *CurrentLayer = BottomLayer;
  while (CurrentStackFrame) {
    if (CurrentStackFrame == SF) break;
    CurrentStackFrame = CurrentStackFrame->getParent();
    CurrentLayer = CurrentLayer->Parent;
  }

  if (!CurrentStackFrame) {
    CurrentStackFrame = BottomStackFrame;
    CurrentLayer = BottomLayer;
  }

  // StackFrame::printJson will do the walk up the chain of StackFrames
  SF->printJson(Out, NL, Space, IsDot, [&](const StackFrame *SF) {
    // SF items begin
    bool HasItem = false;
    unsigned int InnerSpace = Space + 1;

    // Store the last ExprBinding which we will print.
    // Cannot default initialize this.
    BindingsTy::iterator LastI = BottomLayer->Bindings.end();
    if (SF == CurrentStackFrame) {
    LastI = CurrentLayer->Bindings.end();
    for (BindingsTy::iterator I = CurrentLayer->Bindings.begin(); I != CurrentLayer->Bindings.end();
         ++I) {
      // This check is no longer needed, because bindings are stored
      // hierarchically by StackFrames.
      // if (I->first.getStackFrame() != SF)
      //   continue;

      if (!HasItem) {
        HasItem = true;
        Out << '[' << NL;
      }

      const Expr *Ex = I->first;
      (void)Ex;
      assert(Ex != nullptr && "Expected non-null Expr");

      LastI = I;
    }
    }

    if (SF == CurrentStackFrame) {
    for (BindingsTy::iterator I = CurrentLayer->Bindings.begin(); I != CurrentLayer->Bindings.end();
         ++I) {
      // This check is no longer needed, because bindings are stored
      // hierarchically by StackFrames.
      // if (I->first.getStackFrame() != SF)
      //   continue;

      const Expr *Ex = I->first;
      Indent(Out, InnerSpace, IsDot)
          << "{ \"stmt_id\": " << Ex->getID(Ctx) << ", \"kind\": \""
          << Ex->getStmtClassName() << "\", \"pretty\": ";
      Ex->printJson(Out, nullptr, PP, /*AddQuotes=*/true);

      Out << ", \"value\": ";
      I->second.printJson(Out, /*AddQuotes=*/true);

      Out << " }";

      if (I != LastI)
        Out << ',';
      Out << NL;
    }
    }

    if (HasItem)
      Indent(Out, --InnerSpace, IsDot) << ']';
    else
      Out << "null ";

    if (CurrentStackFrame == SF) {
      CurrentLayer = CurrentLayer->Parent;
      CurrentStackFrame = CurrentStackFrame->getParent();
    }
  });

  Indent(Out, --Space, IsDot) << "]}," << NL;
}
