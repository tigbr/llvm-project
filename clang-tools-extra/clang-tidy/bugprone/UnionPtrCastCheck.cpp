//===--- UnionPtrCastCheck.cpp - clang-tidy -------------------------------===//
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

static constexpr llvm::StringLiteral AlwaysAllowCastToVoidPtrOptionName =
    "AlwaysAllowCastToVoidPtr";
static constexpr llvm::StringLiteral AlwaysAllowCastToCharPtrOptionName =
    "AlwaysAllowCastToCharPtr";
static constexpr llvm::StringLiteral IgnoreIfUnionIsFromStdNamespaceOptionName =
    "IgnoreIfUnionIsFromStdNamespace";
static constexpr llvm::StringLiteral IgnoreIfUnionIsFromSystemHeaderOptionName =
    "IgnoreIfUnionIsFromSystemHeader";
static constexpr llvm::StringLiteral UnionBindName = "union";
static constexpr llvm::StringLiteral CastBindName = "cast";

UnionPtrCastCheck::UnionPtrCastCheck(StringRef Name, ClangTidyContext *Context)
    : ClangTidyCheck(Name, Context),
      AlwaysAllowCastToVoidPtr(
          Options.get(AlwaysAllowCastToVoidPtrOptionName, true)),
      AlwaysAllowCastToCharPtr(
          Options.get(AlwaysAllowCastToCharPtrOptionName, true)),
      IgnoreIfUnionIsFromStdNamespace(
          Options.get(IgnoreIfUnionIsFromStdNamespaceOptionName, true)),
      IgnoreIfUnionIsFromSystemHeader(
          Options.get(IgnoreIfUnionIsFromSystemHeaderOptionName, true)) {}

bool UnionPtrCastCheck::isLanguageVersionSupported(
    const LangOptions &LangOpts) const {
  return !LangOpts.ObjC;
}

void UnionPtrCastCheck::registerMatchers(MatchFinder *Finder) {
  // Wrapping the filters in a decl ensures that both branches have the same
  // return type, otherwise a compiler error is given.
  auto StdNamespaceFilter = IgnoreIfUnionIsFromStdNamespace
                                ? decl(unless(isInStdNamespace()))
                                : decl();
  auto SystemHeaderFilter = IgnoreIfUnionIsFromSystemHeader
                                ? decl(unless(isExpansionInSystemHeader()))
                                : decl();
  auto HasPointerToUnionSourceExpr = hasSourceExpression(hasType(
      pointerType(pointee(hasUnqualifiedDesugaredType(recordType(hasDeclaration(
          recordDecl(isUnion(), StdNamespaceFilter, SystemHeaderFilter)
              .bind(UnionBindName))))))));
  auto IsRelevantCastKindAndSourceExpr =
      allOf(hasCastKind(CK_BitCast), HasPointerToUnionSourceExpr);

  Finder->addMatcher(
      implicitCastExpr(hasImplicitDestinationType(isAnyPointer()),
                       IsRelevantCastKindAndSourceExpr)
          .bind(CastBindName),
      this);
  Finder->addMatcher(mapAnyOf(cStyleCastExpr, cxxReinterpretCastExpr)
                         .with(allOf(hasDestinationType(isAnyPointer()),
                                     IsRelevantCastKindAndSourceExpr))
                         .bind(CastBindName),
                     this);
}

static const PointerType* getCastTargetPointerType(const CastExpr *Cast, const MatchFinder::MatchResult &Result) {
#if 0
  QualType Prev;
  QualType Current = Cast->getType();
  do {
    Prev = Current;
    Current.dump();
    if (const PointerType *P = llvm::dyn_cast<PointerType>(Current.getTypePtrOrNull())) {
      llvm::errs() << "Gave diag: " << AnalyzeCast(Union, Cast->getSubExpr(), P->getPointeeType(), Current.getTypePtrOrNull()->getPointeeCXXRecordDecl()) << "\n";
      Current = P->getPointeeType();
    } else if (AllowCastToUnderlyingAliasedType) {
      Current = Current.getSingleStepDesugaredType(*Result.Context);
    } else if (const auto *E = llvm::dyn_cast<ElaboratedType>(Current.getTypePtrOrNull())) {
      AnalyzeCast(Union, Cast->getSubExpr(), E->getNamedType(), Current.getTypePtrOrNull()->getPointeeCXXRecordDecl());
    }
  } while ((Current != Prev));
#else
  QualType CastQualType = Cast->getType();
  const PointerType *CastPointerType = nullptr;
  do {
    CastPointerType = dyn_cast_or_null<PointerType>(CastQualType.getTypePtrOrNull());
    llvm::errs() << CastPointerType << '\n';
    if (const auto *ET = dyn_cast_or_null<ElaboratedType>(CastPointerType)) {
      CastQualType = ET->getNamedType();
    } else {
      CastQualType = CastQualType.getSingleStepDesugaredType(*Result.Context);
    }
  } while (!CastPointerType);
  llvm::errs() << "Return " << CastPointerType << '\n';
  return CastPointerType;
#endif
}

void UnionPtrCastCheck::check(const MatchFinder::MatchResult &Result) {
  const auto *Union = Result.Nodes.getNodeAs<RecordDecl>(UnionBindName);
  const auto *Cast = Result.Nodes.getNodeAs<CastExpr>(CastBindName);
  const PointerType *T = getCastTargetPointerType(Cast, Result);

  llvm::errs() << "T before assert " << T << '\n';
  assert(Union && "Union declaration should be returned in MatchResult!");
  assert(Cast && "Cast expression should be returned in MatchResult!");
  // assert(T && "The target of the cast expression should be a pointer type!");
  llvm::errs() << "T after assert " << T << '\n';

  if (shouldWarn(T, Union))
    diag(Cast->getSubExpr()->getBeginLoc(),
         "the union pointed to by this expression has no field with the type "
         "'%0'") << T->getPointeeType().getAsString();
}

static bool fieldDerivesFrom(const FieldDecl *Field,
                             const CXXRecordDecl *PointeeCXXRecordDecl) {
  const Type *FieldType = Field->getType().getTypePtr();
  const CXXRecordDecl *CXXD = dyn_cast<CXXRecordDecl>(
      FieldType ? FieldType->getAsCXXRecordDecl() : nullptr);
  if (CXXD && PointeeCXXRecordDecl && CXXD->isDerivedFrom(PointeeCXXRecordDecl))
    return true;
  return false;
}

bool UnionPtrCastCheck::shouldWarn(const PointerType *Target, const RecordDecl *Union) const {
  llvm::errs() << "shouldWarn " << Target << '\n';
  if (!Target) return false;
  QualType PointeeQualType = Target->getPointeeType();
;
  if (const auto *PointeeType =
          dyn_cast<BuiltinType>(PointeeQualType.getTypePtr())) {
    if (AlwaysAllowCastToVoidPtr && PointeeType->isVoidType())
      return false;
    if (AlwaysAllowCastToCharPtr && PointeeType->isCharType())
      return false;
  }

  if (Union->isCompleteDefinition()) {
    for (const FieldDecl *Field : Union->fields()) {
      if (PointeeQualType == Field->getType())
        return false;
      if (fieldDerivesFrom(Field, Target->getPointeeCXXRecordDecl()))
        return false;
    }
  }

  return true;
}

} // namespace clang::tidy::bugprone
