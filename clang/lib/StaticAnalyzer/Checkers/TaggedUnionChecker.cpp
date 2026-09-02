#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/BugReporter/CommonBugCategories.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "llvm/ADT/SmallSet.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/APSInt.h"
#include "llvm/Support/FormatVariadic.h"

#include <algorithm>
#include <map>

using namespace clang;
using namespace ento;

namespace {

struct TaggedUnionDecl {
	const RecordDecl *root;
	const RecordDecl *union_decl;
	const FieldDecl *union_field_decl;
	const EnumDecl *enum_decl;
	const FieldDecl *enum_field_decl;
};

struct RecordObject {
	const RecordDecl *type_decl = nullptr;
	const TypedValueRegion *region = nullptr;
};

bool operator==(RecordObject &a, RecordObject &b) {
	return a.type_decl == b.type_decl && a.region == b.region;
}

struct UnionAccess {
	TaggedUnionDecl tagged_union_decl;
	RecordObject which_tagged_union;
	bool IsLoad;
	const FieldDecl *accessed_union_field;
	std::optional<llvm::APSInt> tag_value_apsint;
	const Stmt *access_stmt;
};

struct TaggedUnionChecker : public Checker<check::ASTDecl<TranslationUnitDecl>, check::Location, check::EndAnalysis, check::EndOfTranslationUnit> {

	const BugType BT{this, "inconsistently used tagged union type"};
	mutable std::vector<TaggedUnionDecl> TaggedUnionDecls;
    mutable std::map<const RecordDecl*, std::vector<UnionAccess>> tagged_union_invariants;
	mutable std::vector<UnionAccess> pendingUnionAccesses;
	using vsize_t = std::vector<UnionAccess>::size_type;

    TaggedUnionChecker() { }

	void updateTaggedUnionMappings(UnionAccess &a) const;

	/* Tagged union types are collected in this callback using an ASTMatcher. */
	void checkASTDecl(const TranslationUnitDecl *D, AnalysisManager &Mgr, BugReporter &BR) const;

	/* Collect tagged union mappings. */
	void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;
	void checkEndAnalysis(ExplodedGraph &G, BugReporter &BR, ExprEngine &Eng) const;

	/* Check tagged union mappings and emit warnings when necessary. */
	void checkEndOfTranslationUnit(const TranslationUnitDecl *TU, AnalysisManager& mgr, BugReporter &BR) const;
};
} // end anonymous namespace

static bool isUnion(const FieldDecl *R) {
	return R->getType().getCanonicalType().getTypePtr()->isUnionType();
}

static bool isEnum(const FieldDecl *R) {
	return R->getType().getCanonicalType().getTypePtr()->isEnumeralType();
}

static bool hasMultipleUnionsOrEnums(const RecordDecl *Rec) {
	return llvm::count_if(Rec->fields(), isUnion) > 1 ||
	       llvm::count_if(Rec->fields(), isEnum) > 1;
}

struct MyMatchCallback : public clang::ast_matchers::MatchFinder::MatchCallback {
	std::vector<TaggedUnionDecl> *TaggedUnionDecls;
	MyMatchCallback(std::vector<TaggedUnionDecl> *TaggedUnionDecls) : TaggedUnionDecls{TaggedUnionDecls} {}
	virtual void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override {
		const auto *Root = Result.Nodes.getNodeAs<RecordDecl>("root");
		const auto *UnionField = Result.Nodes.getNodeAs<FieldDecl>("union");
		const auto *TagField = Result.Nodes.getNodeAs<FieldDecl>("tag");

		assert(Root && "Root is missing!");
		assert(UnionField && "UnionField is missing!");
		assert(TagField && "TagField is missing!");
		if (!Root || !UnionField || !TagField)
			return;

		if (hasMultipleUnionsOrEnums(Root))
			return;

		const auto *UnionDef =
			UnionField->getType().getCanonicalType().getTypePtr()->getAsRecordDecl();
		const auto *EnumDef = llvm::dyn_cast<EnumDecl>(
				TagField->getType().getCanonicalType().getTypePtr()->getAsTagDecl());

		TaggedUnionDecl t;
		t.root = Root;
		t.union_decl = UnionDef;
		t.union_field_decl = UnionField;
		t.enum_decl = EnumDef;
		t.enum_field_decl = TagField;
		TaggedUnionDecls->push_back(t);
	}
};

void TaggedUnionChecker::checkASTDecl(const TranslationUnitDecl *D, AnalysisManager &Mgr, BugReporter &BR) const {
	using namespace clang::ast_matchers;

    MyMatchCallback MatchCallback(&this->TaggedUnionDecls);
    MatchFinder Finder;

    const auto NotFromSystemHeaderOrStdNamespace =
        unless(anyOf(isExpansionInSystemHeader(), isInStdNamespace()));

    const auto UnionField =
        fieldDecl(hasType(qualType(hasCanonicalType(recordType(hasDeclaration(
            recordDecl(isUnion(), NotFromSystemHeaderOrStdNamespace))))))).bind("union");

    const auto EnumField = fieldDecl(hasType(qualType(hasCanonicalType(
        enumType(hasDeclaration(enumDecl(NotFromSystemHeaderOrStdNamespace))))))).bind("tag");

    Finder.addMatcher(recordDecl(anyOf(isStruct(), isClass()), has(UnionField), has(EnumField), unless(isImplicit()))
                           .bind("root"), &MatchCallback);
	Finder.matchAST(Mgr.getASTContext());
}

RecordObject getRecordDeclOfSuperRegion(const FieldRegion *FRegion, CheckerContext &C) {
	RecordObject result;

	auto *super_field_region = FRegion->getSuperRegion();
	result.region = super_field_region->getAs<TypedValueRegion>();
	if (!result.region) return result;

	QualType qualtype_desugared = result.region->getDesugaredValueType(C.getASTContext());
	const Type *desugared_type = qualtype_desugared.getTypePtrOrNull();
	if (!desugared_type) return result;
	if (!desugared_type->isRecordType()) return result;

	const RecordType *desugared_record_type = desugared_type->getAsStructureType();
	if (!desugared_record_type) return result; 
	result.type_decl = desugared_record_type->getDecl();

	return result;
}

bool firstIsRightBeforeSecond(const Stmt *UnionStmt, const Stmt *TagStmt, CheckerContext &C) {

	const DynTypedNodeList Parents = C.getAnalysisManager().getASTContext().getParents(*TagStmt);
	if (Parents.size() != 1) 
		return false;

	const CompoundStmt *CS = Parents[0].get<CompoundStmt>();
	if (!CS)
		return false;

	const Stmt *prev = nullptr;
	for (const Stmt *s : CS->body()) {
		if (prev == UnionStmt && s == TagStmt)
			return true;
		prev = s;
	}

	return false;
}

void TaggedUnionChecker::updateTaggedUnionMappings(UnionAccess &a) const {
	if (!a.tag_value_apsint || !a.accessed_union_field) return;
	auto &mappings = tagged_union_invariants[a.which_tagged_union.type_decl];
	for (auto &M : mappings) {
		bool SameTag = llvm::APSInt::isSameValue(*M.tag_value_apsint, *a.tag_value_apsint);
		bool SameField = M.accessed_union_field == a.accessed_union_field;
		if (SameTag && SameField) return;
	}
	mappings.push_back(a);
}

void TaggedUnionChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *Statement, CheckerContext &C) const {

	auto *Region = Loc.getAsRegion();
	if (!Region) return;

	auto *FRegion = Region->getAs<FieldRegion>();
	if (!FRegion) return;

	// FIXME: Handle union fields that are also structs
	// FIXME: Handle nested tagged unions?
	const FieldRegion *super_fieldregion = nullptr;
	bool IsEnumLikeAccess = true;
	RecordObject CandidateTaggedUnion = getRecordDeclOfSuperRegion(FRegion, C);
	if (!CandidateTaggedUnion.type_decl) {
		if (!FRegion->getSuperRegion()) return;
		if (!FRegion->getSuperRegion()->getAs<FieldRegion>()) return;
		super_fieldregion = FRegion->getSuperRegion()->getAs<FieldRegion>();

		CandidateTaggedUnion = getRecordDeclOfSuperRegion(super_fieldregion, C);
		if (!CandidateTaggedUnion.type_decl) return;
		IsEnumLikeAccess = false;
	}

	// I. Check whether the accessed object is a tagged union
	// FIXME: Replace linear search
	TaggedUnionDecl T;
	bool IsTaggedUnion = false;
	for (const TaggedUnionDecl &D : TaggedUnionDecls) {
		if (D.root == CandidateTaggedUnion.type_decl) {
			T = D;
			IsTaggedUnion = true;
			break;
		}
	}
	if (!IsTaggedUnion) return;

	// The accessed field should be the tag field of the tagged union.
	// The tagged union could have additional fields as well, not just the tag.

	// This section implements a heuristic to detect when the union part is
	// initialized before the tag, like for example:
	//
	// t.Union.field1 = 123;
	// t.Kind = kind1;
	//
	// Normally, the checker establishes pairs of (enum constant, union field)
	// upon union accesses, however, when the union is initialized first, the tag
	// value at the moment is outdated, because it is going to be provided
	// later "on the next line".
	//
	// This heuristic also means that the checker does not immediately save
	// the results of an union access as an invariant, because it has to check
	// if there is a reverse initialization sitation coming up.
	//
	if (!IsLoad && IsEnumLikeAccess && FRegion->getDecl() == T.enum_field_decl) {

		// This should be a CFGStmt, since checkLocation is load or store
		const Stmt *access_stmt = C.getCFGElementRef()->getAs<clang::CFGStmt>()->getStmt();
		const BinaryOperator *assignment_stmt = llvm::dyn_cast<BinaryOperator>(access_stmt);
		if (!assignment_stmt) return;

		SVal NewEnumVal = C.getSVal(assignment_stmt->getRHS());
		const llvm::APSInt *new_enum_value_apsint = NewEnumVal.getAsInteger();
		if (!new_enum_value_apsint) new_enum_value_apsint = C.getConstraintManager().getSymVal(C.getState(), NewEnumVal.getAsSymbol());

		// Reverse iteration helps simplify the removal of items
		for (int i = pendingUnionAccesses.size() - 1; 0 <= i; i -= 1) {
			auto &UnionAccess = pendingUnionAccesses[i];

			bool IsReverseInitialization = firstIsRightBeforeSecond(UnionAccess.access_stmt, access_stmt, C);
			IsReverseInitialization &= (UnionAccess.which_tagged_union == CandidateTaggedUnion);
			IsReverseInitialization &= !UnionAccess.IsLoad;
			if (!IsReverseInitialization) return;

			// A matching union assignment was found for this enum assignment.
			UnionAccess.tag_value_apsint = (new_enum_value_apsint ? std::optional{*new_enum_value_apsint} : std::optional<llvm::APSInt>{});
			updateTaggedUnionMappings(UnionAccess);
			pendingUnionAccesses[i] = pendingUnionAccesses[pendingUnionAccesses.size()-1];
			pendingUnionAccesses.pop_back();
		}
	} else if (super_fieldregion && super_fieldregion->getDecl() == T.union_field_decl) {

		MemRegionManager &m = C.getStoreManager().getRegionManager();
		const FieldRegion *enum_field_region = m.getFieldRegion(T.enum_field_decl, CandidateTaggedUnion.region);

		SVal enum_sval = C.getState()->getSVal(enum_field_region, enum_field_region->getValueType());
		const llvm::APSInt *apsint = enum_sval.getAsInteger();
		if (!apsint) apsint = C.getConstraintManager().getSymVal(C.getState(), enum_sval.getAsSymbol());

		UnionAccess a;
		a.tag_value_apsint = (apsint ? std::optional{*apsint} : std::optional<llvm::APSInt>{});
		a.tagged_union_decl = T;
		a.which_tagged_union = CandidateTaggedUnion;
		a.IsLoad = IsLoad;
		a.accessed_union_field = FRegion->getDecl();
		// Should be a CFGStmt, as checkLocation is a load or store
		a.access_stmt = C.getCFGElementRef()->getAs<clang::CFGStmt>()->getStmt();
		pendingUnionAccesses.push_back(a);
	}
}

void TaggedUnionChecker::checkEndAnalysis(ExplodedGraph &G, BugReporter &BR, ExprEngine &Eng) const {
	for (auto &Access : pendingUnionAccesses)
		updateTaggedUnionMappings(Access);
}

void TaggedUnionChecker::checkEndOfTranslationUnit(const TranslationUnitDecl *TU, AnalysisManager& mgr, BugReporter &BR) const {
	for (auto &Access : pendingUnionAccesses)
		updateTaggedUnionMappings(Access);

	for (auto &[tagged_union_decl, mappings] : tagged_union_invariants) {
		std::sort(mappings.begin(), mappings.end(), [] (UnionAccess a, UnionAccess b) {
			return llvm::APSInt::compareValues(*a.tag_value_apsint, *b.tag_value_apsint) < 0;
		});
		vsize_t first = 0;
		for (vsize_t i = 0; i < mappings.size(); i += 1) {
			bool is_new_value = !llvm::APSInt::isSameValue(*mappings[i].tag_value_apsint, *mappings[first].tag_value_apsint);
			bool is_last_value = (i == mappings.size() - 1);
			if (is_new_value) {
				first = i;
			}

			if (!is_new_value && !is_last_value)
				continue;

			if ((is_new_value ? i - first : i - first + 1) > 1) {
				auto &access = mappings[first];
				auto Report = std::make_unique<BasicBugReport>(BT, "inconsistently used tagged union type", PathDiagnosticLocation(access.which_tagged_union.type_decl, BR.getSourceManager()));
				Report->setDeclWithIssue(tagged_union_decl);

				for (vsize_t k = first; k < (is_new_value ? i : mappings.size()); k += 1) {
					const EnumConstantDecl *matched_decl;
					for (const EnumConstantDecl *Enumerator : mappings[k].tagged_union_decl.enum_decl->enumerators()) {
						if (llvm::APSInt::isSameValue(Enumerator->getInitVal(), *mappings[k].tag_value_apsint)) {
							matched_decl = Enumerator;
							break;
						}
					}
					PathDiagnosticLocation ELoc = PathDiagnosticLocation::createBegin(mappings[k].access_stmt, BR.getSourceManager(), mgr.getAnalysisDeclContext(TU));
					const char Format[] = "'{0}' matched with union field '{1}'";
					std::string S = llvm::formatv(Format, matched_decl->getName(), mappings[k].accessed_union_field->getName());
					// Internally, a copy of S is stored in the note
					Report->addNote(S, ELoc);
				}

				BR.emitReport(std::move(Report));
			}
		}
	}
}

void ento::registerTaggedUnionChecker(CheckerManager &Mgr) {
	Mgr.registerChecker<TaggedUnionChecker>();
}

bool ento::shouldRegisterTaggedUnionChecker(const CheckerManager &mgr) {
	return true;
}
