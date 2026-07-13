//===- ExplodedGraph.cpp - Local, Path-Sens. "Exploded Graph" -------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
//  This file defines the template classes ExplodedNode and ExplodedGraph,
//  which represent a path-sensitive, intra-procedural "exploded graph."
//
//===----------------------------------------------------------------------===//

#include "clang/StaticAnalyzer/Core/PathSensitive/ExplodedGraph.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ExprObjC.h"
#include "clang/AST/ParentMap.h"
#include "clang/AST/Stmt.h"
#include "clang/Analysis/ProgramPoint.h"
#include "clang/Analysis/Support/BumpVector.h"
#include "clang/Basic/LLVM.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState_Fwd.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/FoldingSet.h"
#include "llvm/ADT/PointerUnion.h"
#include <cassert>
#include <memory>
#include <optional>

using namespace clang;
using namespace ento;

//===----------------------------------------------------------------------===//
// Cleanup.
//===----------------------------------------------------------------------===//

ExplodedGraph::ExplodedGraph() = default;

ExplodedGraph::~ExplodedGraph() = default;

//===----------------------------------------------------------------------===//
// Node reclamation.
//===----------------------------------------------------------------------===//

bool ExplodedGraph::isInterestingLValueExpr(const Expr *Ex) {
  if (!Ex->isLValue())
    return false;
  return isa<DeclRefExpr, MemberExpr, ObjCIvarRefExpr, ArraySubscriptExpr>(Ex);
}

//===----------------------------------------------------------------------===//
// ExplodedNode.
//===----------------------------------------------------------------------===//

// An NodeGroup's storage type is actually very much like a TinyPtrVector:
// it can be either a pointer to a single ExplodedNode, or a pointer to a
// BumpVector allocated with the ExplodedGraph's allocator. This allows the
// common case of single-node NodeGroups to be implemented with no extra memory.
//
// Consequently, each of the NodeGroup methods have up to four cases to handle:
// 1. The flag is set and this group does not actually contain any nodes.
// 2. The group is empty, in which case the storage value is null.
// 3. The group contains a single node.
// 4. The group contains more than one node.
using ExplodedNodeVector = BumpVector<ExplodedNode *>;
using GroupStorage = llvm::PointerUnion<ExplodedNode *, ExplodedNodeVector *>;

void ExplodedNode::addPredecessor(ExplodedNode *V, ExplodedGraph &G) {
  assert(!V->isSink());
  Preds.addNode(V, G);
  V->Succs.addNode(this, G);
}

void ExplodedNode::NodeGroup::replaceNode(ExplodedNode *node) {
  assert(!getFlag());

  GroupStorage &Storage = reinterpret_cast<GroupStorage&>(P);
  assert(isa<ExplodedNode *>(Storage));
  Storage = node;
  assert(isa<ExplodedNode *>(Storage));
}

void ExplodedNode::NodeGroup::addNode(ExplodedNode *N, ExplodedGraph &G) {
  assert(!getFlag());

  GroupStorage &Storage = reinterpret_cast<GroupStorage&>(P);
  if (Storage.isNull()) {
    Storage = N;
    assert(isa<ExplodedNode *>(Storage));
    return;
  }

  ExplodedNodeVector *V = dyn_cast<ExplodedNodeVector *>(Storage);

  if (!V) {
    // Switch from single-node to multi-node representation.
    auto *Old = cast<ExplodedNode *>(Storage);

    BumpVectorContext &Ctx = G.getNodeAllocator();
    V = new (G.getAllocator()) ExplodedNodeVector(Ctx, 4);
    V->push_back(Old, Ctx);

    Storage = V;
    assert(!getFlag());
    assert(isa<ExplodedNodeVector *>(Storage));
  }

  V->push_back(N, G.getNodeAllocator());
}

unsigned ExplodedNode::NodeGroup::size() const {
  if (getFlag())
    return 0;

  const GroupStorage &Storage = reinterpret_cast<const GroupStorage &>(P);
  if (Storage.isNull())
    return 0;
  if (ExplodedNodeVector *V = dyn_cast<ExplodedNodeVector *>(Storage))
    return V->size();
  return 1;
}

ExplodedNode * const *ExplodedNode::NodeGroup::begin() const {
  if (getFlag())
    return nullptr;

  const GroupStorage &Storage = reinterpret_cast<const GroupStorage &>(P);
  if (Storage.isNull())
    return nullptr;
  if (ExplodedNodeVector *V = dyn_cast<ExplodedNodeVector *>(Storage))
    return V->begin();
  return Storage.getAddrOfPtr1();
}

ExplodedNode * const *ExplodedNode::NodeGroup::end() const {
  if (getFlag())
    return nullptr;

  const GroupStorage &Storage = reinterpret_cast<const GroupStorage &>(P);
  if (Storage.isNull())
    return nullptr;
  if (ExplodedNodeVector *V = dyn_cast<ExplodedNodeVector *>(Storage))
    return V->end();
  return Storage.getAddrOfPtr1() + 1;
}

bool ExplodedNode::isTrivial() const {
  return pred_size() == 1 && succ_size() == 1 &&
         getFirstPred()->getState()->getID() == getState()->getID() &&
         getFirstPred()->succ_size() == 1;
}

const CFGBlock *ExplodedNode::getCFGBlock() const {
  ProgramPoint P = getLocation();
  if (auto BEP = P.getAs<BlockEntrance>())
    return BEP->getBlock();

  // Find the node's current statement in the CFG.
  // FIXME: getStmtForDiagnostics() does nasty things in order to provide
  // a valid statement for body farms, do we need this behavior here?
  if (const Stmt *S = getStmtForDiagnostics())
    return getStackFrame()->getAnalysisDeclContext()->getCFGStmtMap()->getBlock(
        S);

  return nullptr;
}

static const StackFrame *
findTopAutosynthesizedParentStackFrame(const StackFrame *SF) {
  assert(SF->getAnalysisDeclContext()->isBodyAutosynthesized());
  const StackFrame *ParentSF = SF->getParent();
  assert(ParentSF && "We don't start analysis from autosynthesized code");
  while (ParentSF->getAnalysisDeclContext()->isBodyAutosynthesized()) {
    SF = ParentSF;
    ParentSF = SF->getParent();
    assert(ParentSF && "We don't start analysis from autosynthesized code");
  }
  return SF;
}

const Stmt *ExplodedNode::getStmtForDiagnostics() const {
  // We cannot place diagnostics on autosynthesized code.
  // Put them onto the call site through which we jumped into autosynthesized
  // code for the first time.
  const StackFrame *SF = getStackFrame();
  if (SF->getAnalysisDeclContext()->isBodyAutosynthesized()) {
    // It must be a stack frame because we only autosynthesize functions.
    return findTopAutosynthesizedParentStackFrame(SF)->getCallSite();
  }
  // Otherwise, see if the node's program point directly points to a statement.
  // FIXME: Refactor into a ProgramPoint method?
  ProgramPoint P = getLocation();
  if (auto SP = P.getAs<StmtPoint>())
    return SP->getStmt();
  if (auto BE = P.getAs<BlockEdge>())
    return BE->getSrc()->getTerminatorStmt();
  if (auto CE = P.getAs<CallEnter>())
    return CE->getCallExpr();
  if (auto CEE = P.getAs<CallExitEnd>())
    return CEE->getCalleeStackFrame()->getCallSite();
  if (auto PIPP = P.getAs<PostInitializer>())
    return PIPP->getInitializer()->getInit();
  if (auto CEB = P.getAs<CallExitBegin>())
    return CEB->getReturnStmt();
  if (auto FEP = P.getAs<FunctionExitPoint>())
    return FEP->getStmt();
  if (auto LE = P.getAs<LifetimeEnd>())
    return LE->getTriggerStmt();

  return nullptr;
}

const Stmt *ExplodedNode::getNextStmtForDiagnostics() const {
  for (const ExplodedNode *N = getFirstSucc(); N; N = N->getFirstSucc()) {
    if (N->getLocation().isPurgeKind())
      continue;
    if (const Stmt *S = N->getStmtForDiagnostics()) {
      // Check if the statement is '?' or '&&'/'||'.  These are "merges",
      // not actual statement points.
      switch (S->getStmtClass()) {
        case Stmt::ChooseExprClass:
        case Stmt::BinaryConditionalOperatorClass:
        case Stmt::ConditionalOperatorClass:
          continue;
        case Stmt::BinaryOperatorClass: {
          BinaryOperatorKind Op = cast<BinaryOperator>(S)->getOpcode();
          if (Op == BO_LAnd || Op == BO_LOr)
            continue;
          break;
        }
        default:
          break;
      }
      // We found the statement, so return it.
      return S;
    }
  }

  return nullptr;
}

const Stmt *ExplodedNode::getPreviousStmtForDiagnostics() const {
  for (const ExplodedNode *N = getFirstPred(); N; N = N->getFirstPred())
    if (const Stmt *S = N->getStmtForDiagnostics(); S && !isa<CompoundStmt>(S))
      return S;

  return nullptr;
}

const Stmt *ExplodedNode::getCurrentOrPreviousStmtForDiagnostics() const {
  if (const Stmt *S = getStmtForDiagnostics())
    return S;

  return getPreviousStmtForDiagnostics();
}

ExplodedNode *ExplodedGraph::getNode(const ProgramPoint &L,
                                     ProgramStateRef State,
                                     bool IsSink,
                                     bool* IsNew) {
  // Profile 'State' to determine if we already have an existing node.
  llvm::FoldingSetNodeID profile;
  void *InsertPos = nullptr;

  NodeTy::Profile(profile, L, State, IsSink);
  NodeTy* V = Nodes.FindNodeOrInsertPos(profile, InsertPos);

  if (!V) {
    if (!FreeNodes.empty()) {
      V = FreeNodes.back();
      FreeNodes.pop_back();
    }
    else {
      // Allocate a new node.
      V = getAllocator().Allocate<NodeTy>();
    }

    ++NumNodes;
    new (V) NodeTy(L, State, NumNodes, IsSink);

    // Insert the node into the node set and return it.
    Nodes.InsertNode(V, InsertPos);

    if (IsNew) *IsNew = true;
  }
  else
    if (IsNew) *IsNew = false;

  return V;
}

ExplodedNode *ExplodedGraph::createUncachedNode(const ProgramPoint &L,
                                                ProgramStateRef State,
                                                int64_t Id,
                                                bool IsSink) {
  NodeTy *V = getAllocator().Allocate<NodeTy>();
  new (V) NodeTy(L, State, Id, IsSink);
  return V;
}

std::unique_ptr<ExplodedGraph>
ExplodedGraph::trim(ArrayRef<const NodeTy *> Sinks,
                    InterExplodedGraphMap *ForwardMap,
                    InterExplodedGraphMap *InverseMap) const {
  // FIXME: The two-pass algorithm of this function (which was introduced in
  // 2008) is terribly overcomplicated and should be replaced by a single
  // (backward) pass.

  if (Nodes.empty())
    return nullptr;

  using Pass1Ty = llvm::DenseSet<const ExplodedNode *>;
  Pass1Ty Pass1;

  using Pass2Ty = InterExplodedGraphMap;
  InterExplodedGraphMap Pass2Scratch;
  Pass2Ty &Pass2 = ForwardMap ? *ForwardMap : Pass2Scratch;

  SmallVector<const ExplodedNode*, 10> WL1, WL2;

  // ===- Pass 1 (reverse DFS) -===
  for (const auto Sink : Sinks)
    if (Sink)
      WL1.push_back(Sink);

  // Process the first worklist until it is empty.
  while (!WL1.empty()) {
    const ExplodedNode *N = WL1.pop_back_val();

    // Have we already visited this node?  If so, continue to the next one.
    if (!Pass1.insert(N).second)
      continue;

    // If this is the root enqueue it to the second worklist.
    if (N->Preds.empty()) {
      assert(N == getRoot() && "Found non-root node with no predecessors!");
      WL2.push_back(N);
      continue;
    }

    // Visit our predecessors and enqueue them.
    WL1.append(N->Preds.begin(), N->Preds.end());
  }

  // We didn't hit the root? Return with a null pointer for the new graph.
  if (WL2.empty())
    return nullptr;

  assert(WL2.size() == 1 && "There must be only one root!");

  // Create an empty graph.
  std::unique_ptr<ExplodedGraph> G = std::make_unique<ExplodedGraph>();

  // ===- Pass 2 (forward DFS to construct the new graph) -===
  while (!WL2.empty()) {
    const ExplodedNode *N = WL2.pop_back_val();

    auto [Place, Inserted] = Pass2.try_emplace(N);

    // Skip this node if we have already processed it.
    if (!Inserted)
      continue;

    // Create the corresponding node in the new graph and record the mapping
    // from the old node to the new node.
    ExplodedNode *NewN = G->createUncachedNode(N->getLocation(), N->State,
                                               N->getID(), N->isSink());
    Place->second = NewN;

    // Also record the reverse mapping from the new node to the old node.
    if (InverseMap) (*InverseMap)[NewN] = N;

    // If this node is the root, designate it as such in the graph.
    if (N->Preds.empty()) {
      assert(N == getRoot());
      G->designateAsRoot(NewN);
    }

    // In the case that some of the intended predecessors of NewN have already
    // been created, we should hook them up as predecessors.

    // Walk through the predecessors of 'N' and hook up their corresponding
    // nodes in the new graph (if any) to the freshly created node.
    for (const ExplodedNode *Pred : N->Preds) {
      Pass2Ty::iterator PI = Pass2.find(Pred);
      if (PI == Pass2.end())
        continue;

      NewN->addPredecessor(const_cast<ExplodedNode *>(PI->second), *G);
    }

    // In the case that some of the intended successors of NewN have already
    // been created, we should hook them up as successors.  Otherwise, enqueue
    // the new nodes from the original graph that should have nodes created
    // in the new graph.
    for (const ExplodedNode *Succ : N->Succs) {
      Pass2Ty::iterator PI = Pass2.find(Succ);
      if (PI != Pass2.end()) {
        const_cast<ExplodedNode *>(PI->second)->addPredecessor(NewN, *G);
        continue;
      }

      // Enqueue nodes to the worklist that were marked during pass 1.
      if (Pass1.count(Succ))
        WL2.push_back(Succ);
    }
  }

  return G;
}
