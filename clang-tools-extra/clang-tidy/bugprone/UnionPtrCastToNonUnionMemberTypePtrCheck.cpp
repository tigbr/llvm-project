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

void UnionPtrCastToNonUnionMemberTypePtrCheck::registerMatchers(MatchFinder *Finder) {
  auto isPointerToUnion = hasSourceExpression(ignoringParenImpCasts(hasType(pointerType(pointee(hasUnqualifiedDesugaredType(recordType(hasDeclaration(recordDecl(isUnion()).bind(BindNames.Union)))))))));
  Finder->addMatcher(cStyleCastExpr(isPointerToUnion).bind(BindNames.Cast), this);
  Finder->addMatcher(implicitCastExpr(isPointerToUnion).bind(BindNames.Cast), this);
}

void UnionPtrCastToNonUnionMemberTypePtrCheck::check(const MatchFinder::MatchResult &Result) {
  const auto *Union = Result.Nodes.getNodeAs<RecordDecl>(BindNames.Union);
  const CastExpr *Cast = Result.Nodes.getNodeAs<CStyleCastExpr>(BindNames.Cast);
  if (!Cast) {
    Cast = Result.Nodes.getNodeAs<ImplicitCastExpr>(BindNames.Cast);
  }

  if (const Type *cast_target_type = Cast ? Cast->getType().getTypePtrOrNull() : nullptr)
  if (cast_target_type->isPointerType())
  if (const PointerType *pointer_type_casted_to = llvm::dyn_cast<PointerType>(cast_target_type)) {
    QualType pointee_qualtype = pointer_type_casted_to->getPointeeType();
    const Type *pointee_type = pointee_qualtype.getTypePtr();

    bool found = false;
    for (auto it = Union->field_begin(); it != Union->field_end(); it++) {
      if (pointee_qualtype == it->getType()) {
         found = true;
         break;
      }
    }

    if (!found) {
      if (const BuiltinType *built_in_type = llvm::dyn_cast<BuiltinType>(pointee_type)) {
        if (AllowCastToVoidPtr && built_in_type->isVoidType()) return;
        if (AllowCastToCharPtr && built_in_type->isCharType()) return;
      }
      diag(Cast->getBeginLoc(), "bad");
    }
  }
}

} // namespace clang::tidy::bugprone
