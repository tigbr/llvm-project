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

bool UnionPtrCastToNonUnionMemberTypePtrCheck::isLanguageVersionSupported(const LangOptions &LangOpts) const {
  return !LangOpts.ObjC;
}

void UnionPtrCastToNonUnionMemberTypePtrCheck::registerMatchers(MatchFinder *Finder) {
  auto isPointerToUnion = hasSourceExpression(hasType(pointerType(pointee(hasUnqualifiedDesugaredType(recordType(hasDeclaration(recordDecl(isUnion()).bind(UnionBindName))))))));

  // Unless is used here, because in some expressions (e.g. (void*) &my_union)
  // an implicit cast is generated between the explicit cast and the address of expression.
  // Cases like those would be found by both matchers and thus processed twice.
  // This is problematic when both generate a warning.
  Finder->addMatcher(cStyleCastExpr(isPointerToUnion, unless(hasSourceExpression(implicitCastExpr()))).bind(CastBindName), this);
  Finder->addMatcher(implicitCastExpr(isPointerToUnion).bind(CastBindName), this);
}

void UnionPtrCastToNonUnionMemberTypePtrCheck::check(const MatchFinder::MatchResult &Result) {
  const auto *Union = Result.Nodes.getNodeAs<RecordDecl>(UnionBindName);
  const CastExpr *Cast = Result.Nodes.getNodeAs<CastExpr>(CastBindName);

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
  
  // There is no union member with the same type as the target pointers pointee type
  diag(Cast->getBeginLoc(), "bad");
}

} // namespace clang::tidy::bugprone
