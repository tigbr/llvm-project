//===--- RecordPtrCastCheck.cpp - clang-tidy ------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "RecordPtrCastCheck.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"

using namespace clang::ast_matchers;

namespace clang::tidy::bugprone {

const auto RecordBindName = "record";
const auto CastBindName = "cast";
const auto ParentExplicitCastBindName = "parentExplicitCast";

#define InitOption(option_name, default_value)                                 \
  option_name(Options.get(#option_name, default_value))

RecordPtrCastCheck::RecordPtrCastCheck(StringRef Name, ClangTidyContext *Context)
    : ClangTidyCheck(Name, Context),
      InitOption(AlwaysAllowCastToCharPtr, true),
      InitOption(AlwaysAllowCastToVoidPtr, true),
      InitOption(CompareCanonicalTypes, false),
      InitOption(IgnoreIfRecordIsFromStdNamespace, true),
      InitOption(IgnoreIfRecordIsFromSystemHeader, true) {}

bool RecordPtrCastCheck::isLanguageVersionSupported(
    const LangOptions &LangOpts) const {
  return !LangOpts.ObjC;
}

void RecordPtrCastCheck::registerMatchers(MatchFinder *Finder) {
  // Wrapping the filters in a decl ensures that both branches have the same
  // return type, otherwise a compiler error is given.
  auto StdNamespaceFilter = IgnoreIfRecordIsFromStdNamespace
                                ? decl(unless(isInStdNamespace()))
                                : decl();
  auto SystemHeaderFilter = IgnoreIfRecordIsFromSystemHeader
                                ? decl(unless(isExpansionInSystemHeader()))
                                : decl();

  auto BindParentNoOpExplicitCast =
      anyOf(hasParent(explicitCastExpr(hasCastKind(CK_NoOp))
                          .bind(ParentExplicitCastBindName)),
            anything());

  auto HasPointerToRecordSourceExpr =
      hasSourceExpression(ignoringParenImpCasts(hasType(
          qualType(pointerType(pointee(hasUnqualifiedDesugaredType(recordType(
              hasDeclaration(recordDecl(StdNamespaceFilter, SystemHeaderFilter)
                                 .bind(RecordBindName))))))))));

  auto IsRelevantCast =
      allOf(hasType(qualType(isAnyPointer())), hasCastKind(CK_BitCast),
            HasPointerToRecordSourceExpr, BindParentNoOpExplicitCast);

  Finder->addMatcher(
      mapAnyOf(cStyleCastExpr, cxxReinterpretCastExpr, implicitCastExpr)
          .with(IsRelevantCast)
          .bind(CastBindName),
      this);
}

bool RecordPtrCastCheck::notStandardLayoutIfCPP(const RecordDecl *Record) const {
  if (getLangOpts().CPlusPlus)
    if (const auto *CXXRecord = llvm::dyn_cast<CXXRecordDecl>(Record))
      if (Record->isCompleteDefinition() && !CXXRecord->isStandardLayout())
        return true;
  return false;
}

bool RecordPtrCastCheck::castToAllowedPrimitiveTypePtr(
    const PointerType *Target) const {
  if (const auto *PointeeType =
          dyn_cast<BuiltinType>(Target->getPointeeType().getTypePtr())) {
    if (AlwaysAllowCastToVoidPtr && PointeeType->isVoidType())
      return true;
    if (AlwaysAllowCastToCharPtr && PointeeType->isCharType())
      return true;
  }
  return false;
}

static bool fieldDerivesFrom(const FieldDecl *Field,
                             const CXXRecordDecl *PointeeCXXRecordDecl) {
  const Type *FieldType = Field->getType().getTypePtr();
  const CXXRecordDecl *CXXD =
      FieldType ? FieldType->getAsCXXRecordDecl() : nullptr;
  if (CXXD && CXXD->hasDefinition() && PointeeCXXRecordDecl &&
      PointeeCXXRecordDecl->hasDefinition() &&
      CXXD->getDefinition()->isDerivedFrom(
          PointeeCXXRecordDecl->getDefinition()))
    return true;
  return false;
}

static bool pointeeTargetDerivesFrom(const PointerType *Target,
                                     const RecordDecl *Record) {
  const CXXRecordDecl *TargetCXXRDecl = Target->getPointeeCXXRecordDecl();
  const CXXRecordDecl *SourceCXXRDecl = llvm::dyn_cast<CXXRecordDecl>(Record);
  if (TargetCXXRDecl && TargetCXXRDecl->hasDefinition() && SourceCXXRDecl &&
      SourceCXXRDecl->hasDefinition() &&
      SourceCXXRDecl->getDefinition()->isDerivedFrom(
          TargetCXXRDecl->getDefinition()))
    return true;
  return false;
}

bool RecordPtrCastCheck::hasFieldOfType(const PointerType *Target,
                                       const RecordDecl *Record,
                                       const ASTContext *AST) const {
  if (!Record)
    return false;
  for (const FieldDecl *Field : Record->fields()) {
    QualType FieldType = CompareCanonicalTypes
                             ? Field->getType().getCanonicalType()
                             : Field->getType();
    QualType PointeeType = Target->getPointeeType();
    QualType DesugaredPointeeType = PointeeType.getDesugaredType(*AST);
    if (FieldType == PointeeType)
      return true;
    if (FieldType.getUnqualifiedType() ==
        DesugaredPointeeType.getUnqualifiedType())
      if (DesugaredPointeeType.isAtLeastAsQualifiedAs(FieldType, *AST))
        return true;
    // Do not distinguish (struct Foo*) and (Foo*) in C++
    while (!llvm::dyn_cast<TypedefType>(FieldType.getTypePtr()) && !FieldType.isCanonical()) {
      FieldType = FieldType.getSingleStepDesugaredType(*AST);
    }
    if (DesugaredPointeeType == FieldType) {
      return true;
    }
    if (fieldDerivesFrom(Field, Target->getPointeeCXXRecordDecl()))
      return true;
    if (hasFieldOfType(Target, FieldType.getTypePtr()->getAsRecordDecl(), AST))
      return true;
    if (!Record->isUnion())
      break;
  }
  return false;
}

void RecordPtrCastCheck::emitWarning(const CastExpr *Cast, QualType CastQT,
                                    const MatchFinder::MatchResult &Result) {
  auto warningLoc = Cast->getBeginLoc();
  if (const ImplicitCastExpr *ICast = llvm::dyn_cast<ImplicitCastExpr>(Cast))
    if (ICast->isPartOfExplicitCast()) {
      const auto *ParentCast =
          Result.Nodes.getNodeAs<CastExpr>(ParentExplicitCastBindName);
      if (Cast) {
        warningLoc = ParentCast->getBeginLoc();
      }
    }

  diag(warningLoc, "invalid cast from '%0' to '%1'")
      << Cast->getSubExpr()->IgnoreParenImpCasts()->getType().getAsString()
      << CastQT.getAsString();
}

void RecordPtrCastCheck::check(const MatchFinder::MatchResult &Result) {
  const auto *Record = Result.Nodes.getNodeAs<RecordDecl>(RecordBindName);
  const auto *Cast = Result.Nodes.getNodeAs<CastExpr>(CastBindName);

  assert(Record && "Record declaration should be returned in MatchResult!");
  assert(Cast && "Cast expression should be returned in MatchResult!");

  QualType CastQT = CompareCanonicalTypes
                        ? Cast->getType().getCanonicalType()
                        : Cast->getType().getDesugaredType(*Result.Context);
  const auto *Target = dyn_cast<PointerType>(CastQT.getTypePtr());
  if (!Target)
    return;

  if (castToAllowedPrimitiveTypePtr(Target))
    return;

  if (pointeeTargetDerivesFrom(Target, Record))
    return;

  auto RecordName = Cast->getSubExpr()
                        ->IgnoreParenImpCasts()
                        ->getType()
                        .getTypePtr()
                        ->getPointeeType()
                        .getAsString();
  auto PointeeTypeName = Target->getPointeeType().getAsString();
  if (notStandardLayoutIfCPP(Record)) {
    emitWarning(Cast, CastQT, Result);
    diag(Record->getBeginLoc(), "'%0' is not standard layout",
         DiagnosticIDs::Note)
        << RecordName;
  }
  if (!hasFieldOfType(Target, Record, Result.Context)) {
    emitWarning(Cast, CastQT, Result);
    if (Record->isUnion()) {
      diag(Record->getBeginLoc(), "'%0' has no field of type '%1'",
           DiagnosticIDs::Note)
          << RecordName << PointeeTypeName;
    } else {
      diag(Record->getBeginLoc(), "'%0' has no initial subobject of type '%1'",
           DiagnosticIDs::Note)
          << RecordName << PointeeTypeName;
    }
  }
}

} // namespace clang::tidy::bugprone
