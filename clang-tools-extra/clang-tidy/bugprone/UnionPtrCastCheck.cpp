//===--- UnionPtrCastCheck.cpp - clang-tidy ------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "UnionPtrCastCheck.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"

using namespace clang::ast_matchers;

namespace clang::tidy::bugprone {

static constexpr llvm::StringLiteral AlwaysAllowCastToVoidPtrOptionName = "AlwaysAllowCastToVoidPtr";
static constexpr llvm::StringLiteral AlwaysAllowCastToCharPtrOptionName = "AlwaysAllowCastToCharPtr";
static constexpr llvm::StringLiteral AnalyzeUnionsFromStdNamespaceOptionName = "AnalyzeUnionsFromStdNamespace";
static constexpr llvm::StringLiteral AnalyzeUnionsFromSystemHeadersOptionName = "AnalyzeUnionsFromSystemHeaders";
static constexpr llvm::StringLiteral UnionBindName = "union";
static constexpr llvm::StringLiteral CastBindName = "cast";

UnionPtrCastCheck::UnionPtrCastCheck(StringRef Name, ClangTidyContext *Context) : ClangTidyCheck(Name, Context),
      AlwaysAllowCastToVoidPtr(Options.get(AlwaysAllowCastToVoidPtrOptionName, true)),
      AlwaysAllowCastToCharPtr(Options.get(AlwaysAllowCastToCharPtrOptionName, true)),
      AnalyzeUnionsFromStdNamespace(Options.get(AnalyzeUnionsFromStdNamespaceOptionName, false)),
      AnalyzeUnionsFromSystemHeaders(Options.get(AnalyzeUnionsFromSystemHeadersOptionName, false)) { }

bool UnionPtrCastCheck::isLanguageVersionSupported(const LangOptions &LangOpts) const {
  return !LangOpts.ObjC;
}

void UnionPtrCastCheck::registerMatchers(MatchFinder *Finder) {
  // Wrapping the filters in a decl ensures that both branches have the same
  // return type, otherwise a compiler error is given.
  auto StdNamespaceFilter = AnalyzeUnionsFromStdNamespace ? decl(anything()) : decl(unless(isInStdNamespace()));
  auto SystemHeaderFilter = AnalyzeUnionsFromSystemHeaders ? decl(anything()) : decl(unless(isExpansionInSystemHeader()));
  auto HasPointerToUnionSourceExpr = hasSourceExpression(hasType(pointerType(pointee(hasUnqualifiedDesugaredType(recordType(hasDeclaration(recordDecl(isUnion(), StdNamespaceFilter, SystemHeaderFilter).bind(UnionBindName))))))));
  auto IsRelevantCastKindAndSourceExpr = allOf(hasCastKind(CK_BitCast), HasPointerToUnionSourceExpr);

  Finder->addMatcher(implicitCastExpr(hasImplicitDestinationType(isAnyPointer()), IsRelevantCastKindAndSourceExpr).bind(CastBindName), this);
  Finder->addMatcher(mapAnyOf(cStyleCastExpr, cxxReinterpretCastExpr).with(allOf(hasDestinationType(isAnyPointer()), IsRelevantCastKindAndSourceExpr)).bind(CastBindName), this);
}

void UnionPtrCastCheck::check(const MatchFinder::MatchResult &Result) {
  const auto *Union = Result.Nodes.getNodeAs<RecordDecl>(UnionBindName);
  const auto *Cast = Result.Nodes.getNodeAs<CastExpr>(CastBindName);

  assert(Union && "Node for union declaration is not returned in MatchResult!");
  assert(Cast && "Node for cast expression is not returned in MatchResult!");

  const Type *CastType = Cast->getType().getTypePtrOrNull();
  if (const auto *CastPointerType = llvm::dyn_cast<PointerType>(CastType))
    if (shouldWarn(Union, CastPointerType->getPointeeType(), CastType->getPointeeCXXRecordDecl()))
      diag(Cast->getSubExpr()->getBeginLoc(), "the union pointed to by this expression has no field with the type '%0'") << CastPointerType->getPointeeType().getAsString();
}

static bool fieldDerivesFrom(const QualType FieldQualType, const CXXRecordDecl *PointeeCXXRecordDecl) {
  const Type *FieldType = FieldQualType.getTypePtr();
  const CXXRecordDecl *CXXD = llvm::dyn_cast<CXXRecordDecl>(FieldType ? FieldType->getAsCXXRecordDecl() : nullptr);
  if (CXXD && PointeeCXXRecordDecl && CXXD->isDerivedFrom(PointeeCXXRecordDecl)) return true;
  return false;
}

bool UnionPtrCastCheck::shouldWarn(const RecordDecl *Union, const QualType PointeeQualType, const CXXRecordDecl *PointeeCXXRecordDecl) const {
  if (const auto *PointeeType = llvm::dyn_cast<BuiltinType>(PointeeQualType.getTypePtr())) {
    if (AlwaysAllowCastToVoidPtr && PointeeType->isVoidType()) return false;
    if (AlwaysAllowCastToCharPtr && PointeeType->isCharType()) return false;
  }

  if (Union->isCompleteDefinition()) {
    for (const FieldDecl *Field : Union->fields()) {
      if (PointeeQualType == Field->getType()) return false;
      if (fieldDerivesFrom(Field->getType(), PointeeCXXRecordDecl)) return false;
    }
  }

  return true;
}

} // namespace clang::tidy::bugprone
