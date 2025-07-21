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
  auto isPointerToUnion = hasSourceExpression(ignoringParenImpCasts(hasType(pointerType(pointee(hasUnqualifiedDesugaredType(recordType(hasDeclaration(recordDecl(isUnion()).bind(UnionBindName)))))))));
  Finder->addMatcher(cStyleCastExpr(isPointerToUnion).bind(CastBindName), this);
  Finder->addMatcher(implicitCastExpr(isPointerToUnion).bind(CastBindName), this);
}

void UnionPtrCastToNonUnionMemberTypePtrCheck::check(const MatchFinder::MatchResult &Result) {
  const auto *Union = Result.Nodes.getNodeAs<RecordDecl>(UnionBindName);
  const CastExpr *Cast = Result.Nodes.getNodeAs<CStyleCastExpr>(CastBindName);
  if (!Cast) {
    Cast = Result.Nodes.getNodeAs<ImplicitCastExpr>(CastBindName);
  }

  if (const Type *cast_target_type = Cast ? Cast->getType().getTypePtrOrNull() : nullptr)
  if (cast_target_type->isPointerType())
  if (const PointerType *pointer_type_casted_to = llvm::dyn_cast<PointerType>(cast_target_type)) {
    process(Union, Cast, pointer_type_casted_to->getPointeeType());
  } else if (const ElaboratedType *elaborated = llvm::dyn_cast<ElaboratedType>(cast_target_type)) {
    process(Union, Cast, elaborated->getNamedType());
  }
}

void UnionPtrCastToNonUnionMemberTypePtrCheck::process(const RecordDecl *Union, const CastExpr *Cast, QualType pointee_qualtype) {
	bool found = false;
    for (auto it = Union->field_begin(); it != Union->field_end(); it++) {
      if (pointee_qualtype == it->getType()) {
         found = true;
         break;
      }
    }

    if (!found) {
      if (const BuiltinType *built_in_type = llvm::dyn_cast<BuiltinType>(pointee_qualtype.getTypePtr())) {
        if (AllowCastToPtrToVoid && built_in_type->isVoidType()) return;
        if (AllowCastToPtrToChar && built_in_type->isCharType()) return;
      }
      diag(Cast->getBeginLoc(), "bad");
    }
}

} // namespace clang::tidy::bugprone
