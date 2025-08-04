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

static constexpr llvm::StringLiteral AllowCastToPtrToVoidOptionName = "AllowCastToPtrToVoid";
static constexpr llvm::StringLiteral AllowCastToPtrToCharOptionName = "AllowCastToPtrToChar";
static constexpr llvm::StringLiteral UnionBindName = "union";
static constexpr llvm::StringLiteral CastBindName = "cast";

UnionPtrCastToNonUnionMemberTypePtrCheck::UnionPtrCastToNonUnionMemberTypePtrCheck(StringRef Name, ClangTidyContext *Context) : ClangTidyCheck(Name, Context),
      AllowCastToPtrToVoid(Options.get(AllowCastToPtrToVoidOptionName, true)),
      AllowCastToPtrToChar(Options.get(AllowCastToPtrToCharOptionName, true)) { }

bool UnionPtrCastToNonUnionMemberTypePtrCheck::isLanguageVersionSupported(const LangOptions &LangOpts) const {
  return !LangOpts.ObjC;
}

void UnionPtrCastToNonUnionMemberTypePtrCheck::registerMatchers(MatchFinder *Finder) {
  auto isPointerToUnion = hasSourceExpression(hasType(pointerType(pointee(hasUnqualifiedDesugaredType(recordType(hasDeclaration(recordDecl(isUnion()).bind(UnionBindName))))))));
  Finder->addMatcher(implicitCastExpr(isPointerToUnion).bind(CastBindName), this);

  // Ignore expressions where there is an extra implicit cast between the
  // explicit cast and the pointer expression (e.g. (void*) &my_union).
  // These cases should be found by the matcher for implicit casts.
  Finder->addMatcher(cStyleCastExpr(isPointerToUnion, unless(hasSourceExpression(implicitCastExpr()))).bind(CastBindName), this);
}

void UnionPtrCastToNonUnionMemberTypePtrCheck::check(const MatchFinder::MatchResult &Result) {
  const auto *Union = Result.Nodes.getNodeAs<RecordDecl>(UnionBindName);
  assert(Union && "Node for union declaration is not returned to check!");

  const CastExpr *Cast = Result.Nodes.getNodeAs<CastExpr>(CastBindName);
  assert(Cast && "Node for cast expression is not returned to check!");

  const Type *cast_target_type = Cast->getType().getTypePtrOrNull();
  if (cast_target_type && cast_target_type->isPointerType()) {
    if (const PointerType *pointer_type_casted_to = llvm::dyn_cast<PointerType>(cast_target_type)) {
      process(Union, Cast, pointer_type_casted_to->getPointeeType());
    } else if (const ElaboratedType *elaborated = llvm::dyn_cast<ElaboratedType>(cast_target_type)) {
      process(Union, Cast, elaborated->getNamedType());
    }
  }
}

void UnionPtrCastToNonUnionMemberTypePtrCheck::process(const RecordDecl *Union, const CastExpr *Cast, QualType pointee_qualtype) {
  for (auto it = Union->field_begin(); it != Union->field_end(); it++) {
    if (pointee_qualtype == it->getType()) return;
  }

  if (const BuiltinType *BT = llvm::dyn_cast<BuiltinType>(pointee_qualtype.getTypePtr())) {
    if (AllowCastToPtrToVoid && BT->isVoidType()) return;
    if (AllowCastToPtrToChar && BT->isCharType()) return;
  }

  diag(Cast->getBeginLoc(), "the union pointed to by this expression has no field with the type '%0'") << pointee_qualtype.getAsString();
}

} // namespace clang::tidy::bugprone
