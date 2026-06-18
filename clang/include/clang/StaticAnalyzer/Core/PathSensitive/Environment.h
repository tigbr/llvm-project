//===- Environment.h - Map from Stmt* to Locations/Values -------*- C++ -*-===//
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

#ifndef LLVM_CLANG_STATICANALYZER_CORE_PATHSENSITIVE_ENVIRONMENT_H
#define LLVM_CLANG_STATICANALYZER_CORE_PATHSENSITIVE_ENVIRONMENT_H

#include "clang/Analysis/AnalysisDeclContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState_Fwd.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SVals.h"
#include "llvm/ADT/ImmutableMap.h"
#include <utility>

namespace clang {
namespace ento {

class SValBuilder;
class SymbolReaper;

class Layer : public llvm::FoldingSetNode {
  friend class Environment;
  friend class EnvironmentManager;

  using BindingsTy = llvm::ImmutableMap<const Expr *, SVal>;

  const Layer *Parent;
  BindingsTy Bindings;

  Layer(const Layer *P, BindingsTy B)
		: Parent(P), Bindings(B) {}

public:
  static void Profile(llvm::FoldingSetNodeID& ID, const Layer *Parent, BindingsTy Bindings) {
		ID.AddPointer(Parent);
		Bindings.Profile(ID);
  }

  void Profile(llvm::FoldingSetNodeID& ID) const {
    Profile(ID, Parent, Bindings);
	}

  bool operator==(const Layer& RHS) const {
    return Parent == RHS.Parent && Bindings == RHS.Bindings;
  }

  bool isEmpty() const {
    return nullptr == Bindings.getMaxElement();
  }
};

/// An entry in the environment consists of an Expr and an StackFrame.
/// This allows the environment to manage context-sensitive bindings,
/// which is essentially for modeling recursive function analysis, among
/// other things.
class EnvironmentEntry : public std::pair<const Expr *, const StackFrame *> {
public:
  EnvironmentEntry(const Expr *E, const StackFrame *SF);

  const Expr *getExpr() const { return first; }
  const StackFrame *getStackFrame() const { return second; }

  /// Profile an EnvironmentEntry for inclusion in a FoldingSet.
  static void Profile(llvm::FoldingSetNodeID &ID,
                      const EnvironmentEntry &E) {
    ID.AddPointer(E.getExpr());
    ID.AddPointer(E.getStackFrame());
  }

  void Profile(llvm::FoldingSetNodeID &ID) const {
    Profile(ID, *this);
  }
};

/// An immutable map from EnvironmentEntries to SVals.
class Environment {
private:
  friend class EnvironmentManager;
  using BindingsTy = Layer::BindingsTy;

  const StackFrame *BottomStackFrame;
  const Layer *BottomLayer;

  Environment(const StackFrame *SF, const Layer *L) : BottomStackFrame(SF), BottomLayer(L) { }

  SVal lookupExpr(const EnvironmentEntry &E) const;

public:

  using BindingsIteratorType = llvm::ImmutableMap<const Expr*, SVal>::iterator;

  struct iterator {
	// The end iterator is represented as SF == nullptr, L == nullptr,
	// while BindingsIterator and BindingsEnd are arbitrary and undefined.
    const StackFrame *SF;
    const Layer *L;
    BindingsIteratorType BindingsIterator;
    BindingsIteratorType BindingsEnd;

    iterator(
      const clang::StackFrame* const SF,
      const Layer *L,
      BindingsIteratorType BindingsIt,
      BindingsIteratorType BindingsEnd
    ) : SF{SF},
        L{L},
        BindingsIterator{BindingsIt},
        BindingsEnd{BindingsEnd} { }

    bool isEnd() const {
      return !SF && !L;
    }

    bool operator!=(const struct iterator &other) {
      return !this->operator==(other);
    }

    bool operator==(const struct iterator &other) {
	  if (isEnd())
		return other.isEnd();
      return this->SF == other.SF &&
             this->L == other.L &&
             this->BindingsIterator == other.BindingsIterator &&
             this->BindingsEnd == other.BindingsEnd;
    }

    std::pair<EnvironmentEntry, SVal> operator*() {
      assert(!isEnd() && "Dereferencing the environment end iterator is invalid!");
      return {EnvironmentEntry((*BindingsIterator).first, SF), (*BindingsIterator).second};
    }

    iterator operator++() {
 	  assert(SF && L && "Incrementing the environment end iterator is invalid!");
      if (BindingsIterator != BindingsEnd) {
        BindingsIterator++;
      }
      while (BindingsIterator == BindingsEnd) {
        if (SF->getParent()) {
          SF = SF->getParent();
          L = L->Parent;
          BindingsIterator = L->Bindings.begin();
          BindingsEnd = L->Bindings.end();
 		} else {
          BindingsIterator = L->Bindings.begin();
          BindingsEnd = L->Bindings.end();
          SF = nullptr;
          L = nullptr;
		  break;
        }
      }
      return *this;
    }

    void validateInvariants() const;
  };

  iterator begin() const {
    if (BottomLayer->isEmpty())
      return end();
    return iterator(BottomStackFrame,
                    BottomLayer,
                    BottomLayer->Bindings.begin(),
                    BottomLayer->Bindings.end()); }

  iterator end() const {
    return iterator(nullptr,
                    nullptr,
                    BottomLayer->Bindings.begin(),
                    BottomLayer->Bindings.end()); }

  /// Fetches the current binding of the expression in the
  /// Environment.
  SVal getSVal(const EnvironmentEntry&, SValBuilder&) const;

  /// Profile - Used to profile the contents of this object for inclusion
  ///  in a FoldingSet.
  void Profile(llvm::FoldingSetNodeID& ID) const {
    ID.AddPointer(BottomStackFrame);
    ID.AddPointer(BottomLayer);
  }

  bool operator==(const Environment& RHS) const {
    return BottomLayer == RHS.BottomLayer && BottomStackFrame == RHS.BottomStackFrame;
  }

  void printJson(raw_ostream &Out, const ASTContext &Ctx,
                 const StackFrame *SF = nullptr, const char *NL = "\n",
                 unsigned int Space = 0, bool IsDot = false) const;

  Environment validateInvariants() const;
  Environment validateInvariants(const EnvironmentEntry &Entry, SVal V, bool Invalidate) const;
};

class EnvironmentManager {

  using FactoryTy = Environment::BindingsTy::Factory;

  llvm::FoldingSet<Layer> Layers;
  FactoryTy F;

  const Layer* makeLayer(const Layer *Parent, Environment::BindingsTy Bindings);

public:
  EnvironmentManager(llvm::BumpPtrAllocator &Allocator) : F(Allocator) {}

  Environment getInitialEnvironment(const StackFrame *SF) {
    return Environment(SF, makeLayer(/*Parent=*/nullptr, F.getEmptyMap()));
  }

  /// Bind a symbolic value to the given environment entry.
  Environment bindExpr(Environment Env, const EnvironmentEntry &E, SVal V,
                       bool Invalidate);

  Environment removeDeadBindings(Environment Env,
                                 SymbolReaper &SymReaper,
                                 ProgramStateRef state);
};

} // namespace ento

} // namespace clang

#endif // LLVM_CLANG_STATICANALYZER_CORE_PATHSENSITIVE_ENVIRONMENT_H
