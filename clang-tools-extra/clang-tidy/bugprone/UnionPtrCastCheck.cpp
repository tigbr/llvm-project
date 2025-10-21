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

static constexpr llvm::StringLiteral UnionBindName = "union";
static constexpr llvm::StringLiteral CastBindName = "cast";

// If there is a user specified value for the option, then get that value,
// otherwise use a default. The # converts its argument to a string literal.
// So the option's expected name in the configuration is the same as the name
// of the corressponding class member holding the option's value.
#define InitOption(option_name, default_value)                                 \
  option_name(Options.get(#option_name, default_value))

UnionPtrCastCheck::UnionPtrCastCheck(StringRef Name, ClangTidyContext *Context)
    : ClangTidyCheck(Name, Context),
      InitOption(AllowCastToBaseClass, true),
      InitOption(AllowCastToSubField, true),
      InitOption(AlwaysAllowCastToCharPtr, true),
      InitOption(AlwaysAllowCastToVoidPtr, true),
      InitOption(CompareCanonicalTypes, false),
      InitOption(IgnoreIfUnionIsFromStdNamespace, true),
      InitOption(IgnoreIfUnionIsFromSystemHeader, true) { }

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

void UnionPtrCastCheck::check(const MatchFinder::MatchResult &Result) {
  const auto *Union = Result.Nodes.getNodeAs<RecordDecl>(UnionBindName);
  const auto *Cast = Result.Nodes.getNodeAs<CastExpr>(CastBindName);

  assert(Union && "Union declaration should be returned in MatchResult!");
  assert(Cast && "Cast expression should be returned in MatchResult!");

  QualType CastQT = CompareCanonicalTypes
                        ? Cast->getType().getCanonicalType()
                        : Cast->getType().getDesugaredType(*Result.Context);

  const auto *T = dyn_cast<PointerType>(CastQT.getTypePtr());
  if (shouldWarn(T, Union))
    diag(Cast->getSubExpr()->getBeginLoc(),
         "the union pointed to by this expression has no field with the type "
         "'%0'")
        << T->getPointeeType().getAsString();
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

static bool langOptIsC(const LangOptions &Options) {
	if (Options.C99) return true;
}

bool UnionPtrCastCheck::hasFieldOfType(const PointerType *Target, const RecordDecl *Record) const {
  if (!Record)
    return false;
  for (const FieldDecl *Field : Record->fields()) {
    QualType FieldType = CompareCanonicalTypes
                             ? Field->getType().getCanonicalType()
                             : Field->getType();
    if (FieldType == Target->getPointeeType())
      return true;
    if (AllowCastToBaseClass && fieldDerivesFrom(Field, Target->getPointeeCXXRecordDecl()))
      return true;
    if (langOptIsC(getLangOpts()) && AllowCastToSubField && hasFieldOfType(Target, FieldType.getTypePtr()->getAsRecordDecl()))
      return true;
    if (!Record->isUnion())
      break;
  }
  return false;
}

bool UnionPtrCastCheck::shouldWarn(const PointerType *Target, const RecordDecl *Union) const {
  if (!Target)
    return false;

  if (const auto *PointeeType =
          dyn_cast<BuiltinType>(Target->getPointeeType().getTypePtr())) {
    if (AlwaysAllowCastToVoidPtr && PointeeType->isVoidType())
      return false;
    if (AlwaysAllowCastToCharPtr && PointeeType->isCharType())
      return false;
  }

  if (hasFieldOfType(Target, Union))
    return false;

  return true;
}

} // namespace clang::tidy::bugprone
