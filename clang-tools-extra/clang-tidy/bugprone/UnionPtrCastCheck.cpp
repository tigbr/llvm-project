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

static constexpr llvm::StringLiteral AlwaysAllowCastToVoidPtrOptionName = "AlwaysAllowCastToVoidPtr";
static constexpr llvm::StringLiteral AlwaysAllowCastToCharPtrOptionName = "AlwaysAllowCastToCharPtr";
static constexpr llvm::StringLiteral IgnoreIfUnionIsFromStdNamespaceOptionName = "IgnoreIfUnionIsFromStdNamespace";
static constexpr llvm::StringLiteral IgnoreIfUnionIsFromSystemHeaderOptionName = "IgnoreIfUnionIsFromSystemHeader";
static constexpr llvm::StringLiteral CompareNormalizedTypesOptionName = "CompareNormalizedTypes";
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
          Options.get(IgnoreIfUnionIsFromSystemHeaderOptionName, true)),
      CompareNormalizedTypes(Options.get(CompareNormalizedTypesOptionName, false)) { }

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

// static RecordDecl* Create(const ASTContext &C, TagKind TK, DeclContext *DC, SourceLocation StartLoc, SourceLocation IdLoc, IdentifierInfo *Id, RecordDecl *PrevDecl=nullptr)
// DeclContext::addDecl <- is this how FieldDecl can be added?

// This normalization logic is implemented to handle typedef and using
// statements in two differe ways.
// Some users might consider a typedef or a using as a hard boundary
// between types.
static QualType getNormalizedType(QualType QT, const ASTContext &ASTCTX) {
  const Type *T = QT.getTypePtr();
  while (true) {
    if (auto *E = dyn_cast<ElaboratedType>(T)) {
      llvm::errs() << "ElaboratedType: " << QT.getAsString() << '\n';
      QT = E->getNamedType();
      T = QT.getTypePtr();
    } else if (auto *E = dyn_cast<PointerType>(T)) {
      llvm::errs() << "PointerType: " << QT.getAsString() << '\n';
      return ASTCTX.getPointerType(getNormalizedType(E->getPointeeType(), ASTCTX));
    } else if (auto *E = dyn_cast<RecordType>(T)) {
      // RecordDecl::create(ASTCTX, nullptr, )
      return ASTCTX.getPointerType();
    } else {
      llvm::errs() << "Else: " << QT.getAsString() << '\n';
      QualType Desugared = QT.getSingleStepDesugaredType(ASTCTX);
      llvm::errs() << "Desugared: " << Desugared.getAsString() << '\n';
      if (Desugared == QT) {
        break;
      }
      QT = Desugared;
    }
  }
  return QT;
}

// Peel off typedef or using layers one at a time until a PointerType is found.
static const PointerType* getCastTargetPointerType(const CastExpr *Cast, const ASTContext &ASTCtx) {
  QualType Prev;
  QualType CastQualType = Cast->getType();
  llvm::errs() << CastQualType.getAsString() << '\n';
  const PointerType *CastPointerType = nullptr;
  do {
    Prev = CastQualType;
    CastPointerType = dyn_cast_or_null<PointerType>(CastQualType.getTypePtrOrNull());
    if (const auto *ET = dyn_cast_or_null<ElaboratedType>(CastQualType.getTypePtrOrNull())) {
      CastQualType = ET->getNamedType();
    } else {
      CastQualType = CastQualType.getSingleStepDesugaredType(ASTCtx);
    }
  } while ((Prev != CastQualType) && !CastPointerType);
  return CastPointerType;
}

void UnionPtrCastCheck::check(const MatchFinder::MatchResult &Result) {
  const auto *Union = Result.Nodes.getNodeAs<RecordDecl>(UnionBindName);
  const auto *Cast = Result.Nodes.getNodeAs<CastExpr>(CastBindName);
  llvm::errs() << getNormalizedType(Cast->getType(), *Result.Context).getAsString() << '\n';
  return;
  const PointerType *T = getCastTargetPointerType(Cast, *Result.Context);

  assert(Union && "Union declaration should be returned in MatchResult!");
  assert(Cast && "Cast expression should be returned in MatchResult!");
  assert(T && "The target of the cast expression should be a pointer type!");

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
  if (const auto *PointeeType =
          dyn_cast<BuiltinType>(Target->getPointeeType().getTypePtr())) {
    if (AlwaysAllowCastToVoidPtr && PointeeType->isVoidType())
      return false;
    if (AlwaysAllowCastToCharPtr && PointeeType->isCharType())
      return false;
  }

  if (Union->isCompleteDefinition()) {
    for (const FieldDecl *Field : Union->fields()) {
      if (Target->getPointeeType() == Field->getType())
        return false;
      if (fieldDerivesFrom(Field, Target->getPointeeCXXRecordDecl()))
        return false;
    }
  }

  return true;
}

} // namespace clang::tidy::bugprone
