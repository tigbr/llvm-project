#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/BugReporter/CommonBugCategories.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

// ~/forraskodok/llvm-project/build/bin/clang -cc1 -analyze -analyzer-checker=core /tmp/recursivemain.c

#if 0

void TaggedUnionMemberCountCheck::registerMatchers(MatchFinder *Finder) {
  Finder->addMatcher(
      recordDecl(
          anyOf(isStruct(), isClass()),
          has(fieldDecl(hasType(qualType(hasCanonicalType(recordType()))))
                  .bind("union")),
          has(fieldDecl(hasType(qualType(hasCanonicalType(enumType()))))
                  .bind("tags")))
          .bind("root"),
      this);
}

static bool isUnion(const FieldDecl *R) {
  return R->getType().getCanonicalType().getTypePtr()->isUnionType();
}

static bool isEnum(const FieldDecl *R) {
  return R->getType().getCanonicalType().getTypePtr()->isEnumeralType();
}

static bool hasMultipleUnionsOrEnums(const RecordDecl *Rec) {
  return llvm::count_if(Rec->fields(), isUnion) > 1 ||
         llvm::count_if(Rec->fields(), isEnum) > 1;
}

static bool signEquals(const llvm::APSInt &A, const llvm::APSInt &B) {
  return (A.isNegative() && B.isNegative()) ||
         (A.isStrictlyPositive() && B.isStrictlyPositive()) ||
         (A.isZero() && B.isZero());
}

static bool greaterBySign(const llvm::APSInt &A, const llvm::APSInt &B) {
  return (A.isNonNegative() && B.isNegative()) ||
         (A.isStrictlyPositive() && B.isNonPositive());
}

bool TaggedUnionMemberCountCheck::isCountingEnumLikeName(
    StringRef Name) const noexcept {
  if (llvm::any_of(ParsedCountingEnumPrefixes,
                   [&Name](const StringRef &Prefix) -> bool {
                     return Name.starts_with_insensitive(Prefix);
                   }))
    return true;
  if (llvm::any_of(ParsedCountingEnumSuffixes,
                   [&Name](const StringRef &Suffix) -> bool {
                     return Name.ends_with_insensitive(Suffix);
                   }))
    return true;
  return false;
}

size_t TaggedUnionMemberCountCheck::getNumberOfValidEnumValues(
    const EnumDecl *Ed) noexcept {
  bool FoundMax = false;
  llvm::APSInt MaxTagValue;
  llvm::SmallSet<llvm::APSInt, 32> EnumValues;

  size_t CeCount = 0;
  bool CeIsLast = false;
  llvm::APSInt CeValue = llvm::APSInt::get(0);

  for (const auto &Enumerator : Ed->enumerators()) {
    const llvm::APSInt Val = Enumerator->getInitVal();
    EnumValues.insert(Val);
    if (FoundMax) {
      if (greaterBySign(Val, MaxTagValue) ||
          (signEquals(Val, MaxTagValue) && Val > MaxTagValue))
        MaxTagValue = Val;
    } else {
      MaxTagValue = Val;
      FoundMax = true;
    }

    if (EnableCountingEnumHeuristic) {
      if (isCountingEnumLikeName(Enumerator->getName())) {
        CeIsLast = true;
        CeValue = Val;
        CeCount += 1;
        CountingEnumConstantDecl = Enumerator;
      } else {
        CeIsLast = false;
      }
    }
  }

  size_t ValidValuesCount = EnumValues.size();
  if (CeCount == 1 && CeIsLast && CeValue == MaxTagValue) {
    ValidValuesCount -= 1;
  } else {
    CountingEnumConstantDecl = nullptr;
  }

  return ValidValuesCount;
}

#endif

using namespace clang;
using namespace ento;

namespace {

class TaggedUnionChecker : public Checker<check::BranchCondition> {

  const BugType BT{this, "Tagged union checker"};

public:
  void checkBranchCondition(const clang::Stmt *Statement, CheckerContext &C) const;
};
} // end anonymous namespace

void TaggedUnionChecker::checkBranchCondition(const clang::Stmt *Statement, CheckerContext &C) const {
  // if (const IdentifierInfo *II = Call.getCalleeIdentifier())
  //   if (II->isStr("main")) {
  //     ExplodedNode *N = C.generateErrorNode();
  //     auto Report = std::make_unique<PathSensitiveBugReport>(BT, BT.getCategory(), N);
  //     C.emitReport(std::move(Report));
  //   }
}

void ento::registerTaggedUnionChecker(CheckerManager &Mgr) {
  Mgr.registerChecker<TaggedUnionChecker>();
}

bool ento::shouldRegisterTaggedUnionChecker(const CheckerManager &mgr) {
  return true;
}
