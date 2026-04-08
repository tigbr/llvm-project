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

class Stmt;

namespace ento {

class Environment;
class EnvironmentManager;
class SValBuilder;
class SymbolReaper;

/// An entry in the environment consists of a Stmt and an LocationContext.
/// This allows the environment to manage context-sensitive bindings,
/// which is essentially for modeling recursive function analysis, among
/// other things.
class EnvironmentEntry : public std::pair<const Stmt *,
                                          const StackFrameContext *> {
public:
  EnvironmentEntry(const Stmt *s, const LocationContext *L);

  const Stmt *getStmt() const { return first; }
  const LocationContext *getLocationContext() const { return second; }

  /// Profile an EnvironmentEntry for inclusion in a FoldingSet.
  static void Profile(llvm::FoldingSetNodeID &ID,
                      const EnvironmentEntry &E) {
    ID.AddPointer(E.getStmt());
    ID.AddPointer(E.getLocationContext());
  }

  void Profile(llvm::FoldingSetNodeID &ID) const {
    Profile(ID, *this);
  }
};

struct Layer {
	llvm::ImmutableMap<const Stmt*, SVal> ExprBindings;
	unsigned ParentLayerIndex;

	void Profile(llvm::FoldingSetNodeID& ID) const {
		ID.AddInteger(ParentLayerIndex);
		ExprBindings.Profile(ID);
	} 

	bool operator==(const Layer other) const {
		return ExprBindings == other.ExprBindings && ParentLayerIndex == other.ParentLayerIndex;
	}

	bool operator<(const Layer other) const {
		return ParentLayerIndex < other.ParentLayerIndex;
	}
};

class EnvironmentManager {
private:
  friend class Environment;

  llvm::ImmutableMap<Layer, unsigned>::Factory LayerFactory;
  llvm::ImmutableMap<const Stmt*, SVal>::Factory BindingsFactory;

  llvm::ImmutableMap<Layer, unsigned> IndexOf;
  std::vector<Layer> Layers;

  unsigned saveLayer(Layer NewLayer) {
    const unsigned *UpdatedLayerIndex = IndexOf.lookup(NewLayer);
    if (UpdatedLayerIndex) {
      return *UpdatedLayerIndex;
    } else {
      Layers.push_back(NewLayer);
      IndexOf = LayerFactory.add(IndexOf, NewLayer, Layers.size() - 1);
      return Layers.size()-1;
    }
  }

public:
  EnvironmentManager(llvm::BumpPtrAllocator &Allocator) : LayerFactory(Allocator), BindingsFactory(Allocator), IndexOf{LayerFactory.getEmptyMap()} {
    saveLayer(Layer{BindingsFactory.getEmptyMap(), 0});
  }

  inline Environment getInitialEnvironment(const LocationContext *Location);

  /// Bind a symbolic value to the given environment entry.
  Environment bindExpr(const Environment *Env, const EnvironmentEntry &E, SVal V,
                       bool Invalidate);

  Environment removeDeadBindings(Environment Env,
                                 SymbolReaper &SymReaper,
                                 ProgramStateRef state);
};

/// An immutable map from EnvironemntEntries to SVals.
class Environment {
private:
  friend class EnvironmentManager;

  unsigned BottomLayerIndex;
  const LocationContext *BottomLocation;

  Environment(unsigned Idx, const LocationContext *Location) : BottomLayerIndex{Idx}, BottomLocation{Location} {}

  SVal lookupExpr(const EnvironmentManager&, const EnvironmentEntry &E) const;

public:

#if 1
  struct iterator {
    const EnvironmentManager *EnvMgr;
    const LocationContext *BottomLocation;
	unsigned BottomLayerIndex;
    llvm::ImmutableMap<const Stmt*, SVal>::iterator BindingsIterator;
    llvm::ImmutableMap<const Stmt*, SVal>::iterator BindingsEnd;

    iterator(const clang::ento::EnvironmentManager* EnvMgr, const clang::LocationContext* const BottomLocation, const unsigned int BottomLayerIndex, llvm::ImmutableMap<const clang::Stmt*, clang::ento::SVal>::iterator BindingsIt, const unsigned int&, llvm::ImmutableMap<const clang::Stmt*, clang::ento::SVal>::iterator BindingsEnd)
    : EnvMgr{EnvMgr}, BottomLocation{BottomLocation}, BottomLayerIndex{BottomLayerIndex}, BindingsIterator{BindingsIt}, BindingsEnd{BindingsEnd} { }

    bool operator!=(const struct iterator &other) {
      return !this->operator==(other);
    }

    bool operator==(const struct iterator &other) {
      return this->EnvMgr == other.EnvMgr && this->BottomLocation == other.BottomLocation && this->BottomLayerIndex == other.BottomLayerIndex && this->BindingsIterator == other.BindingsIterator && this->BindingsEnd == other.BindingsEnd;
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
        BottomLayerIndex = EnvMgr->Layers[BottomLayerIndex].ParentLayerIndex;
        BindingsIterator = EnvMgr->Layers[BottomLayerIndex].ExprBindings.begin();
        BindingsEnd = EnvMgr->Layers[BottomLayerIndex].ExprBindings.end();
      }
      if (BindingsIterator == BindingsEnd) {
        *this = iterator(EnvMgr, nullptr, 0, EnvMgr->Layers[0].ExprBindings.end(), 0, EnvMgr->Layers[0].ExprBindings.end());
      }
      return *this;
    }
  };

  iterator begin(const EnvironmentManager *EnvMgr) const { return iterator(EnvMgr, BottomLocation, BottomLayerIndex, EnvMgr->Layers[BottomLayerIndex].ExprBindings.begin(), BottomLayerIndex, EnvMgr->Layers[BottomLayerIndex].ExprBindings.end()); }
  iterator end(const EnvironmentManager *EnvMgr) const { return iterator(EnvMgr, nullptr, 0, EnvMgr->Layers[0].ExprBindings.end(), 0, EnvMgr->Layers[0].ExprBindings.end()); }
#endif

  const LocationContext* getLocationContext() const;

  /// Fetches the current binding of the expression in the
  /// Environment.
  SVal getSVal(const EnvironmentManager&, const EnvironmentEntry &E, SValBuilder &svalBuilder) const;

  /// Profile - Profile the contents of an Environment object for use
  ///  in a FoldingSet.
  static void Profile(llvm::FoldingSetNodeID& ID, const Environment *Env) {
    ID.AddInteger(Env->BottomLayerIndex);
    ID.AddPointer(Env->BottomLocation);
  }

  /// Profile - Used to profile the contents of this object for inclusion
  ///  in a FoldingSet.
  void Profile(llvm::FoldingSetNodeID& ID) const {
    Profile(ID, this);
  }

  bool operator==(const Environment& RHS) const {
    return BottomLocation == RHS.BottomLocation && BottomLayerIndex == RHS.BottomLayerIndex;
  }

  void printJson(raw_ostream &Out, EnvironmentManager &EnvMgr, const ASTContext &Ctx,
                 const LocationContext *LCtx = nullptr, const char *NL = "\n",
                 unsigned int Space = 0, bool IsDot = false) const;
};

Environment EnvironmentManager::getInitialEnvironment(const LocationContext *Location) {
  return Environment(0, Location);
}

} // namespace ento

} // namespace clang

#endif // LLVM_CLANG_STATICANALYZER_CORE_PATHSENSITIVE_ENVIRONMENT_H
