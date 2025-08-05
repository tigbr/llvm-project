//===--- UnionPtrCastToNonUnionMemberTypePtrCheck.cpp - clang-tidy ------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "UnionPtrCastToNonUnionMemberTypePtrCheck.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"

using namespace clang::ast_matchers;

namespace clang::tidy::bugprone {

static constexpr llvm::StringLiteral AlwaysAllowCastToPtrToVoidOptionName = "AlwaysAllowCastToPtrToVoid";
static constexpr llvm::StringLiteral AlwaysAllowCastToPtrToCharOptionName = "AlwaysAllowCastToPtrToChar";
static constexpr llvm::StringLiteral UnionBindName = "union";
static constexpr llvm::StringLiteral CastBindName = "cast";

UnionPtrCastToNonUnionMemberTypePtrCheck::UnionPtrCastToNonUnionMemberTypePtrCheck(StringRef Name, ClangTidyContext *Context) : ClangTidyCheck(Name, Context),
      AlwaysAllowCastToPtrToVoid(Options.get(AlwaysAllowCastToPtrToVoidOptionName, true)),
      AlwaysAllowCastToPtrToChar(Options.get(AlwaysAllowCastToPtrToCharOptionName, true)) { }

bool UnionPtrCastToNonUnionMemberTypePtrCheck::isLanguageVersionSupported(const LangOptions &LangOpts) const {
  return !LangOpts.ObjC;
}

void UnionPtrCastToNonUnionMemberTypePtrCheck::registerMatchers(MatchFinder *Finder) {
  auto hasPointerToUnionSourceExpr = hasSourceExpression(hasType(pointerType(pointee(hasUnqualifiedDesugaredType(recordType(hasDeclaration(recordDecl(isUnion()).bind(UnionBindName))))))));
  auto isRelevantCastKindAndSourceExpr = allOf(hasCastKind(CK_BitCast), hasPointerToUnionSourceExpr);
  Finder->addMatcher(implicitCastExpr(hasImplicitDestinationType(isAnyPointer()), isRelevantCastKindAndSourceExpr).bind(CastBindName), this);
  Finder->addMatcher(cStyleCastExpr(hasDestinationType(isAnyPointer()), isRelevantCastKindAndSourceExpr).bind(CastBindName), this);
}

void UnionPtrCastToNonUnionMemberTypePtrCheck::check(const MatchFinder::MatchResult &Result) {
  const auto *Union = Result.Nodes.getNodeAs<RecordDecl>(UnionBindName);
  const auto *Cast = Result.Nodes.getNodeAs<CastExpr>(CastBindName);
  assert(Union && "Node for union declaration is not returned in MatchResult!");
  assert(Cast && "Node for cast expression is not returned in MatchResult!");
  const Type *CastTargetType = Cast->getType().getTypePtrOrNull();
  if (const auto *PointerTypeCastedTo = llvm::dyn_cast<PointerType>(CastTargetType)) {
    AnalyzeCast(Union, Cast->getSubExpr(), PointerTypeCastedTo->getPointeeType());
  } else if (const auto *elaborated = llvm::dyn_cast<ElaboratedType>(CastTargetType)) {
    AnalyzeCast(Union, Cast->getSubExpr(), elaborated->getNamedType());
  }
}

void UnionPtrCastToNonUnionMemberTypePtrCheck::AnalyzeCast(const RecordDecl *Union, const Expr *SubExpression, QualType PointeeQualType) {
  if (Union->isCompleteDefinition()) {
    for (auto it = Union->field_begin(); it != Union->field_end(); it++) {
      if (PointeeQualType == it->getType()) return;
    }
    if (const auto *BT = llvm::dyn_cast<BuiltinType>(PointeeQualType.getTypePtr())) {
      if (AlwaysAllowCastToPtrToVoid && BT->isVoidType()) return;
      if (AlwaysAllowCastToPtrToChar && BT->isCharType()) return;
    }
  }
  diag(SubExpression->getBeginLoc(), "the union pointed to by this expression has no field with the type '%0'") << PointeeQualType.getAsString();
}

} // namespace clang::tidy::bugprone
