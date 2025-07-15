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
  auto isPointerToUnion = hasType(pointerType(pointee(hasUnqualifiedDesugaredType(recordType(hasDeclaration(recordDecl(isUnion()).bind(BindNames.Union)))))));
  Finder->addMatcher(cStyleCastExpr(hasSourceExpression(ignoringParenImpCasts(isPointerToUnion))).bind(BindNames.Cast), this);
}

void UnionPtrCastToNonUnionMemberTypePtrCheck::check(const MatchFinder::MatchResult &Result) {
  const auto *Cast  = Result.Nodes.getNodeAs<CStyleCastExpr>(BindNames.Cast);
  const auto *Union = Result.Nodes.getNodeAs<RecordDecl>(BindNames.Union);

  if (const Type *cast_target_type = Cast->getTypeAsWritten().getTypePtrOrNull())
  if (cast_target_type->isPointerType())
  if (const PointerType *pointer_type_casted_to = llvm::dyn_cast<PointerType>(cast_target_type)) {
    QualType pointee_type = pointer_type_casted_to->getPointeeType();

    bool found = false;
    for (auto it = Union->field_begin(); it != Union->field_end(); it++) {
      if (pointee_type == it->getType()) {
         found = true;
         break;
      }
    }
    
    if (!found) {
      diag(Cast->getLParenLoc(), "bad");
    }
  }
}

} // namespace clang::tidy::bugprone
