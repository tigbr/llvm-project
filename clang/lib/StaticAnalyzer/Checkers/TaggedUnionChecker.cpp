#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/BugReporter/CommonBugCategories.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

// ~/forraskodok/llvm-project/build/bin/clang -cc1 -analyze -analyzer-checker=core /tmp/recursivemain.c

using namespace clang;
using namespace ento;

namespace {
class TaggedUnionChecker : public Checker<check::PreCall> {

  const BugType BT{this, "Tagged union checker"};

public:
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};
} // end anonymous namespace

void TaggedUnionChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  if (const IdentifierInfo *II = Call.getCalleeIdentifier())
    if (II->isStr("main")) {
      ExplodedNode *N = C.generateErrorNode();
      auto Report = std::make_unique<PathSensitiveBugReport>(BT, BT.getCategory(), N);
      C.emitReport(std::move(Report));
    }
}

void ento::registerTaggedUnionChecker(CheckerManager &Mgr) {
  Mgr.registerChecker<TaggedUnionChecker>();
}

bool ento::shouldRegisterTaggedUnionChecker(const CheckerManager &mgr) {
  return true;
}
