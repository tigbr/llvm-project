//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "AlwaysDereferencedVariableCheck.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"

using namespace clang::ast_matchers;

namespace clang::tidy::readability {

#define BN(Name) static const StringRef Name = #Name;
	BN(UnaryOperatorBindName);
	BN(ArraySubscriptExprBindName);
	BN(PtrVariableDeclBindName);
	BN(StdOptionalVariableDeclBindName);
	BN(ArrowMemberExprBindName);
	BN(FunctionPtrCallBindName);
	BN(StdOptionalCallToMethodValueBindName);
	BN(StdOptionalCallToStarOperatorBindName);
	BN(StdOptionalArrowOperatorBindName);
	BN(StdUniquePtrVariableBindName);
	BN(StdSharedPtrVariableBindName);
	BN(StdSharedPtrStarDereferenceBindName);
	BN(CXXOperatorCallBindName);
	BN(TranslationUnitBindName)

	AlwaysDereferencedVariableCheck *Check = nullptr;

	void AlwaysDereferencedVariableCheck::registerMatchers(MatchFinder *Finder) {
		llvm::errs() << "AlwaysDereferencedVariableCheck::registerMatchers called\n";
		Check = this;
		Finder->addMatcher(translationUnitDecl().bind(TranslationUnitBindName), this);
		llvm::errs() << "AlwaysDereferencedVariableCheck::registerMatchers returned\n";
	}

	struct DeclStatistic {
		unsigned Usages;
		unsigned Dereferences;
	};

	struct PointersCallback : public clang::ast_matchers::MatchFinder::MatchCallback {

		std::map<const Decl*, DeclStatistic> DeclStats;

		void run(const MatchFinder::MatchResult &Result) override {
			const Decl *D = Result.Nodes.getNodeAs<Decl>(PtrVariableDeclBindName);
			if (const NamedDecl *ND = dyn_cast<NamedDecl>(D)) {
				if (ND->getName() == "previousFrame") {
					DeclStats[D].Usages += 1;
					ND->dump();
				}
			}

			const UnaryOperator *UO = Result.Nodes.getNodeAs<UnaryOperator>(UnaryOperatorBindName);
			if (UO && UO->getOpcode() == UO_Deref) {
				if (const NamedDecl *ND = dyn_cast<NamedDecl>(D))
					if (ND->getName() == "previousFrame") {
						DeclStats[D].Dereferences += 1;
						UO->dump();
					}
				return;
			}

			const ArraySubscriptExpr *ASE = Result.Nodes.getNodeAs<ArraySubscriptExpr>(ArraySubscriptExprBindName);
			if (ASE) {
				DeclStats[D].Dereferences += 1;
				return;
			}

			const MemberExpr *ME = Result.Nodes.getNodeAs<MemberExpr>(ArrowMemberExprBindName);
			if (ME) {
				DeclStats[D].Dereferences += 1;
				return;
			}

			const CallExpr *CE = Result.Nodes.getNodeAs<CallExpr>(FunctionPtrCallBindName);
			if (CE) {
				DeclStats[D].Dereferences += 1;
				return;
			}
		}
	};

	struct StdOptionalsCallback : public clang::ast_matchers::MatchFinder::MatchCallback {

		std::map<const Decl*, DeclStatistic> DeclStats;

		void run(const MatchFinder::MatchResult &Result) override {
			const Decl *D = Result.Nodes.getNodeAs<Decl>(StdOptionalVariableDeclBindName);
			DeclStats[D].Usages += 1;

			const CXXMemberCallExpr *MC = Result.Nodes.getNodeAs<CXXMemberCallExpr>(StdOptionalCallToMethodValueBindName);
			if (MC) {
				DeclStats[D].Dereferences += 1;
				return;
			}

			const CXXOperatorCallExpr *OC = Result.Nodes.getNodeAs<CXXOperatorCallExpr>(StdOptionalCallToStarOperatorBindName);
			if (OC) {
				DeclStats[D].Dereferences += 1;
				return;
			}

			const MemberExpr *ME = Result.Nodes.getNodeAs<MemberExpr>(StdOptionalArrowOperatorBindName);
			if (ME) {
				DeclStats[D].Dereferences += 1;
				return;
			}
		}
	};

	struct StdUniquePtrCallback : public clang::ast_matchers::MatchFinder::MatchCallback {

		std::map<const Decl*, DeclStatistic> DeclStats;

		void run(const MatchFinder::MatchResult &Result) override {
			const Decl *D = Result.Nodes.getNodeAs<Decl>(StdUniquePtrVariableBindName);
			DeclStats[D].Usages += 1;

			const CXXOperatorCallExpr *CO = Result.Nodes.getNodeAs<CXXOperatorCallExpr>(CXXOperatorCallBindName);
			if (CO) {
				if (CO->getOperator() == OO_Star) {
					// llvm::errs() << "CO && CO->getOperator() == OO_Star\n";
					DeclStats[D].Dereferences += 1;
					return;
				}
				if (CO->getOperator() == OO_Arrow) {
					// llvm::errs() << "CO && CO->getOperator() == OO_Arrow\n";
					DeclStats[D].Dereferences += 1;
					return;
				}
			}
		}
	};

	struct StdSharedPtrCallback : public clang::ast_matchers::MatchFinder::MatchCallback {

		std::map<const Decl*, DeclStatistic> DeclStats;

		void run(const MatchFinder::MatchResult &Result) override {
			const Decl *D = Result.Nodes.getNodeAs<Decl>(StdSharedPtrVariableBindName);
			DeclStats[D].Usages += 1;

			const CXXOperatorCallExpr *CO = Result.Nodes.getNodeAs<CXXOperatorCallExpr>(CXXOperatorCallBindName);
			if (CO) {
				if (CO->getOperator() == OO_Star) {
					// llvm::errs() << "CO && CO->getOperator() == OO_Star\n";
					DeclStats[D].Dereferences += 1;
					return;
				}
				if (CO->getOperator() == OO_Arrow) {
					// llvm::errs() << "CO && CO->getOperator() == OO_Arrow\n";
					DeclStats[D].Dereferences += 1;
					return;
				}
			}
		}
	};

	void AlwaysDereferencedVariableCheck::check(const MatchFinder::MatchResult &Result) {
		llvm::errs() << "AlwaysDereferencedVariableCheck::check called\n";

		const TranslationUnitDecl *TUD = Result.Nodes.getNodeAs<TranslationUnitDecl>(TranslationUnitBindName);
		// if (TUD) {
		// 	TUD->dump();
		// }

		clang::ast_matchers::MatchFinder Finder;

		PointersCallback CBP;
		auto IPC = ignoringParenCasts;
		auto declRefToPtrVar = declRefExpr(hasDeclaration(varDecl(hasType(pointerType())).bind(PtrVariableDeclBindName)));
		Finder.addMatcher(declRefToPtrVar, &CBP);
		Finder.addMatcher(unaryOperator(hasUnaryOperand(IPC(declRefToPtrVar))).bind(UnaryOperatorBindName), &CBP);
		Finder.addMatcher(arraySubscriptExpr(anyOf(allOf(hasLHS(IPC(declRefToPtrVar)), hasRHS(ignoringParenCasts(integerLiteral(equals(0))))), allOf(hasLHS(ignoringParenCasts(integerLiteral(equals(0)))), hasRHS(IPC(declRefToPtrVar))))).bind(ArraySubscriptExprBindName), &CBP);
		Finder.addMatcher(memberExpr(isArrow(), hasObjectExpression(IPC(declRefToPtrVar))).bind(ArrowMemberExprBindName), &CBP);
		Finder.addMatcher(callExpr(callee(expr(IPC(declRefToPtrVar)))).bind(FunctionPtrCallBindName), &CBP);

		StdOptionalsCallback CBSO;
		auto StdOptionalVariable = varDecl(hasType(qualType(hasCanonicalType(recordType(hasDeclaration(recordDecl(hasName("optional"), isInStdNamespace()))))))).bind(StdOptionalVariableDeclBindName);
		auto declRefToStdOptional = declRefExpr(hasDeclaration(StdOptionalVariable));
		Finder.addMatcher(declRefToStdOptional, &CBSO);
		Finder.addMatcher(cxxMemberCallExpr(on(IPC(declRefToStdOptional)), callee(cxxMethodDecl(hasName("value")))).bind(StdOptionalCallToMethodValueBindName), &CBSO);
		Finder.addMatcher(cxxOperatorCallExpr(hasUnaryOperand(IPC(declRefToStdOptional)), hasOverloadedOperatorName("*")).bind(StdOptionalCallToStarOperatorBindName), &CBSO);
		Finder.addMatcher(memberExpr(isArrow(), hasObjectExpression(cxxOperatorCallExpr(hasUnaryOperand(IPC(declRefToStdOptional))))).bind(StdOptionalArrowOperatorBindName), &CBSO);

		StdUniquePtrCallback CBUP;
		auto StdUniquePtrVariable = varDecl(hasType(qualType(hasCanonicalType(hasDeclaration(namedDecl(hasName("::std::unique_ptr"))))))).bind(StdUniquePtrVariableBindName);
		auto declRefToStdUniquePtr = declRefExpr(hasDeclaration(StdUniquePtrVariable));
		Finder.addMatcher(declRefToStdUniquePtr, &CBUP);
		Finder.addMatcher(cxxOperatorCallExpr(hasUnaryOperand(IPC(declRefToStdUniquePtr))).bind(CXXOperatorCallBindName), &CBUP);

		StdSharedPtrCallback CBSP;
		auto StdSharedPtrVariable = varDecl(hasType(qualType(hasCanonicalType(hasDeclaration(namedDecl(hasName("::std::shared_ptr"))))))).bind(StdSharedPtrVariableBindName);
		auto declRefToStdSharedPtr = declRefExpr(hasDeclaration(StdSharedPtrVariable));
		Finder.addMatcher(declRefToStdSharedPtr, &CBSP);
		Finder.addMatcher(cxxOperatorCallExpr(hasUnaryOperand(IPC(declRefToStdSharedPtr))).bind(CXXOperatorCallBindName), &CBSP);

#if 0
		parmVarDecl(hasType(lValueReferenceType(pointee(qualType(unless(isConstQualified()), hasDeclaration(anyOf(classTemplateDecl(isInStdNamespace(), anyOf(hasName("::std::shared_ptr"))), classTemplateSpecializationDecl(isInStdNamespace(), anyOf(hasName("::std::shared_ptr"))))))))))
#endif

			Finder.matchAST(*Result.Context);

		llvm::errs() << "started for loop at line " << __LINE__ << " \n";
		for (auto& [D, Stats] : CBP.DeclStats) {
			if (const NamedDecl *ND = dyn_cast<NamedDecl>(D))
				if (ND->getName() == "previousFrame")
					llvm::errs() << "Dereferences: " << Stats.Dereferences << " Usages: " << Stats.Usages << "\n";
			if (Stats.Usages == Stats.Dereferences * 2)
				diag(D->getLocation(), "pointer is always dereferenced, consider changing it to a reference");
		}
		llvm::errs() << "finished for loop\n";

		llvm::errs() << "started for loop at line " << __LINE__ << " \n";
		for (auto& [D, Stats] : CBSO.DeclStats) {
			// llvm::errs() << "DeclsStats of " << D << " Usages: " << Stats.Usages << " Dereferences: " << Stats.Dereferences << '\n';
			if (Stats.Usages == Stats.Dereferences * 2)
				diag(D->getLocation(), "this std::optional is always dereferenced, consider using the underlying type directly");
		}
		llvm::errs() << "finished for loop\n";

		llvm::errs() << "started for loop at line " << __LINE__ << " \n";
		for (auto& [D, Stats] : CBUP.DeclStats) {
			// llvm::errs() << Stats.Usages << ' ' << Stats.Dereferences << '\n';
			if (Stats.Usages == Stats.Dereferences * 2)
				diag(D->getLocation(), "this std::unique_ptr variable is always dereferenced, consider using a reference instead");
		}
		llvm::errs() << "finished for loop\n";

		llvm::errs() << "started for loop at line " << __LINE__ << " \n";
		for (auto& [D, Stats] : CBSP.DeclStats)
			if (Stats.Usages == Stats.Dereferences * 2)
				diag(D->getLocation(), "this std::shared_ptr variable is always dereferenced, consider using a reference instead");
		llvm::errs() << "finished for loop\n";

	llvm::errs() << "AlwaysDereferencedVariableCheck::check returns\n";
}

} // namespace clang::tidy::readability
