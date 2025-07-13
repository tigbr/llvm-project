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

static const struct {
	std::string_view Union = "union";
	std::string_view Cast = "cast";
} BindNames;

void UnionPtrCastToNonUnionMemberTypePtrCheck::registerMatchers(MatchFinder *Finder) {
  // Finder->addMatcher(cStyleCastExpr().bind("x"), this);
  // Finder->addMatcher(cStyleCastExpr(hasSourceExpression(hasType(pointerType(pointee(recordType(hasDeclaration(recordDecl(isUnion()).bind(BindNames.Union)))))))).bind(BindNames.Cast), this);
  auto isPointerToUnion = hasType(pointerType(pointee(hasUnqualifiedDesugaredType(recordType(hasDeclaration(recordDecl(isUnion()).bind(BindNames.Union)))))));
  Finder->addMatcher(cStyleCastExpr(hasSourceExpression(ignoringParenImpCasts(isPointerToUnion))).bind(BindNames.Cast), this);
}

void UnionPtrCastToNonUnionMemberTypePtrCheck::check(const MatchFinder::MatchResult &Result) {
  const auto *Cast  = Result.Nodes.getNodeAs<CStyleCastExpr>(BindNames.Cast);
  const auto *Union = Result.Nodes.getNodeAs<RecordDecl>(BindNames.Union);

  if (Cast && Union) {
	Cast->dump();
  }

  if (const auto *cast = Result.Nodes.getNodeAs<CStyleCastExpr>("x"))
  if (const Type *type_casted_to = cast->getTypeAsWritten().getTypePtrOrNull())
  if (type_casted_to->isPointerType())
  if (const PointerType *pointer_type_casted_to = llvm::dyn_cast<PointerType>(type_casted_to)) // TODO: Get canonical type, it might be behind possible typedef and using statements
  if (const Expr *casted_expr = cast->getSubExpr())
  if (const UnaryOperator *unary_op = llvm::dyn_cast<UnaryOperator>(casted_expr))
  if (unary_op->getOpcode() == UO_AddrOf)
  if (const Expr *expr_whose_addr_was_taken = unary_op->getSubExpr())
  if (const Type *addr_taken_type = expr_whose_addr_was_taken->getType().getTypePtrOrNull()) 
  if (addr_taken_type->isUnionType())
  if (const RecordDecl *union_recorddecl = addr_taken_type->getAsRecordDecl()) {
    QualType type_of_expr_whose_addr_was_taken = expr_whose_addr_was_taken->getType();
    QualType pointee_type = pointer_type_casted_to->getPointeeType();
    bool type_casted_to_is_in_union = false;
    for (auto it = union_recorddecl->field_begin(); it != union_recorddecl->field_end(); it++) {
      if (pointee_type == it->getType()) {
         type_casted_to_is_in_union = true;
         break;
      }
    }
    
    if (!type_casted_to_is_in_union) {
      diag(cast->getLParenLoc(), "bad");
    }
  }
}

} // namespace clang::tidy::bugprone
