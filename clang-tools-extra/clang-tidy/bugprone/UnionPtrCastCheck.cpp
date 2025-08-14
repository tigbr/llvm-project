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
  auto stdNamespaceFilter = AnalyzeUnionsFromStdNamespace ? decl(anything()) : decl(unless(isInStdNamespace()));
  auto systemHeaderFilter = AnalyzeUnionsFromSystemHeaders ? decl(anything()) : decl(unless(isExpansionInSystemHeader()));
  auto hasPointerToUnionSourceExpr = hasSourceExpression(hasType(pointerType(pointee(hasUnqualifiedDesugaredType(recordType(hasDeclaration(recordDecl(isUnion(), stdNamespaceFilter, systemHeaderFilter).bind(UnionBindName))))))));
  auto isRelevantCastKindAndSourceExpr = allOf(hasCastKind(CK_BitCast), hasPointerToUnionSourceExpr);

  Finder->addMatcher(implicitCastExpr(hasImplicitDestinationType(isAnyPointer()), isRelevantCastKindAndSourceExpr).bind(CastBindName), this);
  Finder->addMatcher(mapAnyOf(cStyleCastExpr, cxxReinterpretCastExpr).with(allOf(hasDestinationType(isAnyPointer()), isRelevantCastKindAndSourceExpr)).bind(CastBindName), this);
}

void UnionPtrCastCheck::check(const MatchFinder::MatchResult &Result) {
  const auto *Union = Result.Nodes.getNodeAs<RecordDecl>(UnionBindName);
  const auto *Cast = Result.Nodes.getNodeAs<CastExpr>(CastBindName);
  assert(Union && "Node for union declaration is not returned in MatchResult!");
  assert(Cast && "Node for cast expression is not returned in MatchResult!");
  const Type *CastTargetType = Cast->getType().getTypePtrOrNull();
  if (const auto *P = llvm::dyn_cast<PointerType>(CastTargetType))
    AnalyzeCast(Union, Cast->getSubExpr(), P->getPointeeType(), CastTargetType->getPointeeCXXRecordDecl());
}

void UnionPtrCastCheck::AnalyzeCast(const RecordDecl *Union, const Expr *SubExpression, QualType PointeeQualType, const CXXRecordDecl *PointeeCXXRecordDecl) {
  if (const auto *T = llvm::dyn_cast<BuiltinType>(PointeeQualType.getTypePtr())) {
    if (AlwaysAllowCastToVoidPtr && T->isVoidType()) return;
    if (AlwaysAllowCastToCharPtr && T->isCharType()) return;
  }
  if (Union->isCompleteDefinition()) {
    for (FieldDecl *D : Union->fields()) {
      if (PointeeQualType == D->getType()) return;
      const Type *FieldType = D->getType().getTypePtr();
      const CXXRecordDecl *CXXD = llvm::dyn_cast<CXXRecordDecl>(FieldType ? FieldType->getAsCXXRecordDecl() : nullptr);
      if (CXXD && PointeeCXXRecordDecl && CXXD->isDerivedFrom(PointeeCXXRecordDecl)) return;
    }
  }
  diag(SubExpression->getBeginLoc(), "the union pointed to by this expression has no field with the type '%0'") << PointeeQualType.getAsString();
}

} // namespace clang::tidy::bugprone
