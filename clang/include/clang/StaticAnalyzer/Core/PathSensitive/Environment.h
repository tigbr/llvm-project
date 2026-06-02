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

class Environment;
class EnvironmentManager;
class SValBuilder;
class SymbolReaper;

/// An entry in the environment consists of a Expr and an StackFrame.
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

struct Layer : public llvm::FoldingSetNode {
	llvm::ImmutableMap<const Expr*, SVal> ExprBindings;
	Layer *ParentLayer;

	Layer(llvm::ImmutableMap<const Expr*, SVal> Bindings, Layer *ParentLayer) : ExprBindings{ExprBindings}, ParentLayer{ParentLayer} { }

	void Profile(llvm::FoldingSetNodeID& ID) const {
		ID.AddPointer(ParentLayer);
		ExprBindings.Profile(ID);
	} 

	bool operator==(const Layer other) const {
		return ExprBindings == other.ExprBindings && ParentLayer == other.ParentLayer;
	}

	bool operator<(const Layer other) const {
		return ParentLayer < other.ParentLayer;
	}
};

class EnvironmentManager {
private:
  friend class Environment;

  llvm::ImmutableMap<Layer, unsigned>::Factory LayerFactory;
  llvm::ImmutableMap<const Expr*, SVal>::Factory BindingsFactory;

  llvm::ImmutableMapRef<Layer, unsigned> IndexOf;
  llvm::FoldingSet<Layer> Layers;
  Layer *EmptyLayer;

  Layer* saveLayer(Layer L);

public:
  EnvironmentManager(llvm::BumpPtrAllocator &Allocator) : LayerFactory(Allocator), BindingsFactory(Allocator), IndexOf{LayerFactory.getEmptyMap(), LayerFactory}, EmptyLayer{nullptr} {
    EmptyLayer = saveLayer(Layer{BindingsFactory.getEmptyMap(), nullptr});
  }

  inline Environment getInitialEnvironment(const StackFrame *Location);

  /// Bind a symbolic value to the given environment entry.
  Environment bindExpr(const Environment *Env, const EnvironmentEntry &E, SVal V,
                       bool Invalidate);

  Environment removeDeadBindings(Environment Env,
                                 SymbolReaper &SymReaper,
                                 ProgramStateRef state);
};

class Environment {
private:
  friend class EnvironmentManager;

  Layer *BottomLayer;
  const StackFrame *BottomLocation;

  Environment(Layer *BottomLayer, const StackFrame *Location) : BottomLayer{BottomLayer}, BottomLocation{Location} {}

  SVal lookupExpr(const EnvironmentManager&, const EnvironmentEntry &E) const;

public:

  using BindingsIteratorType = llvm::ImmutableMap<const Expr*, SVal>::iterator;

#if 1
  struct iterator {
    const StackFrame *BottomLocation;
	const Layer *BottomLayer;
    BindingsIteratorType BindingsIterator;
    BindingsIteratorType BindingsEnd;

    iterator(
      const clang::StackFrame* const BottomLocation,
      const Layer *BottomLayer,
      BindingsIteratorType BindingsIt,
      BindingsIteratorType BindingsEnd
    ) : BottomLocation{BottomLocation},
        BottomLayer{BottomLayer},
        BindingsIterator{BindingsIt},
        BindingsEnd{BindingsEnd} { }

    bool operator!=(const struct iterator &other) {
      return !this->operator==(other);
    }

    bool operator==(const struct iterator &other) {
      return this->BottomLocation == other.BottomLocation && this->BottomLayer == other.BottomLayer && this->BindingsIterator == other.BindingsIterator && this->BindingsEnd == other.BindingsEnd;
    }

    std::pair<EnvironmentEntry, SVal> operator*() {
      return {EnvironmentEntry((*BindingsIterator).first, BottomLocation), (*BindingsIterator).second};
    }

    iterator operator++() {
      if (BindingsIterator != BindingsEnd) {
        BindingsIterator++;
      }
      while (BindingsIterator == BindingsEnd && BottomLocation->getParent()) {
        BottomLocation = BottomLocation->getParent();
        BottomLayer = BottomLayer->ParentLayer;
        BindingsIterator = BottomLayer->ExprBindings.begin();
        BindingsEnd = BottomLayer->ExprBindings.end();
      }
      if (BindingsIterator == BindingsEnd) {
        BindingsIterator = BottomLayer->ExprBindings.begin();
        BindingsEnd = BottomLayer->ExprBindings.begin();
        BottomLocation = nullptr;
        BottomLayer = nullptr;
      }
      return *this;
    }
  };

  iterator begin(const EnvironmentManager *EnvMgr) const {
    return iterator(BottomLocation,
                    BottomLayer,
                    BottomLayer->ExprBindings.begin(),
                    BottomLayer->ExprBindings.end()); }
  iterator end(const EnvironmentManager *EnvMgr) const {
    return iterator(nullptr,
                    nullptr,
                    BottomLayer->ExprBindings.begin(),
                    BottomLayer->ExprBindings.end()); }
#endif

  const StackFrame* getStackFrame() const;

  /// Fetches the current binding of the expression in the
  /// Environment.
  SVal getSVal(const EnvironmentManager&, const EnvironmentEntry &E, SValBuilder &svalBuilder) const;

  /// Profile - Profile the contents of an Environment object for use
  ///  in a FoldingSet.
  static void Profile(llvm::FoldingSetNodeID& ID, const Environment *Env) {
    ID.AddPointer(Env->BottomLayer);
    ID.AddPointer(Env->BottomLocation);
  }

  /// Profile - Used to profile the contents of this object for inclusion
  ///  in a FoldingSet.
  void Profile(llvm::FoldingSetNodeID& ID) const {
    Profile(ID, this);
  }

  bool operator==(const Environment& RHS) const {
    return BottomLocation == RHS.BottomLocation && BottomLayer == RHS.BottomLayer;
  }

  void printJson(raw_ostream &Out, EnvironmentManager &EnvMgr, const ASTContext &Ctx,
                 const StackFrame *SF = nullptr, const char *NL = "\n",
                 unsigned int Space = 0, bool IsDot = false) const;
};

Environment EnvironmentManager::getInitialEnvironment(const StackFrame *Location) {
  return Environment(EmptyLayer, Location);
}

} // namespace ento

} // namespace clang

#endif // LLVM_CLANG_STATICANALYZER_CORE_PATHSENSITIVE_ENVIRONMENT_H
