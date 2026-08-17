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
	const FieldDecl *accessed_union_field = nullptr;
	std::optional<llvm::APSInt> tag_value_apsint;
	const Stmt *access_stmt;
};

class TaggedUnionChecker;

class MyMatchCallback : public clang::ast_matchers::MatchFinder::MatchCallback {
	const TaggedUnionChecker * const C;

public:
	std::vector<TaggedUnionDecl> TaggedUnions;

	std::vector<const FieldDecl*> field_decls;
	llvm::SmallSet<llvm::APSInt, 32> enum_values;

	virtual void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override;
	MyMatchCallback(const TaggedUnionChecker * const Checker) : C{Checker} {}
};

class TaggedUnionChecker : public Checker<check::ASTDecl<TranslationUnitDecl>, check::Location, check::EndAnalysis, check::EndOfTranslationUnit> {

	const BugType BT{this, "Inconsistent tagged union access!"};
    mutable std::map<const RecordDecl*, std::vector<UnionAccess>> tagged_union_invariants;
	mutable std::vector<UnionAccess> pendingUnionAccesses;
	using vsize_t = std::vector<UnionAccess>::size_type;

	void updateTaggedUnionMappings(UnionAccess &a) const;
    mutable MyMatchCallback MatchCallback;
    mutable clang::ast_matchers::MatchFinder Finder;

public:

    TaggedUnionChecker() : MatchCallback{this} {
		using namespace clang::ast_matchers;
		Finder.addMatcher(recordDecl(
	      anyOf(isStruct(), isClass()),
	      has(fieldDecl(hasType(qualType(hasCanonicalType(recordType()))))
	              .bind("union")),
	      has(fieldDecl(hasType(qualType(hasCanonicalType(enumType()))))
	              .bind("tags")))
	      .bind("root"),
	    &MatchCallback);
	}

	/* Tagged union types are collected in this callback using an ASTMatcher. */
	void checkASTDecl(const TranslationUnitDecl *D, AnalysisManager &Mgr, BugReporter &BR) const;

	/* Tagged Union Accesses */
	void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;

	/*  */
	void checkEndAnalysis(ExplodedGraph &G, BugReporter &BR, ExprEngine &Eng) const;

	/* The observed usage patterns of tagged union types are evaluated in this phase. */
	/* Warnings are emitted as necessary. */
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

void MyMatchCallback::run(const clang::ast_matchers::MatchFinder::MatchResult &Result) {

	const auto *Root = Result.Nodes.getNodeAs<RecordDecl>("root");
	const auto *UnionField = Result.Nodes.getNodeAs<FieldDecl>("union");
	const auto *TagField = Result.Nodes.getNodeAs<FieldDecl>("tags");

	assert(Root && "Root is missing!");
	assert(UnionField && "UnionField is missing!");
	assert(TagField && "TagField is missing!");
	if (!Root || !UnionField || !TagField)
	  return;

	if (!isUnion(UnionField))
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
	this->TaggedUnions.push_back(t);
}

RecordObject getRecordDeclOfSuperRegion(const FieldRegion *field_region, CheckerContext &C) {
	RecordObject result;

	auto *super_field_region = field_region->getSuperRegion();
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

bool firstIsRightBeforeSecondInCompoundStmt(const Stmt *unionAccess, const Stmt *tagAccess, const CompoundStmt *compoundStmt, CheckerContext &C) {
	const Stmt *prev = nullptr;
	for (const Stmt *s : compoundStmt->body()) {
		if (prev == unionAccess && s == tagAccess) return true;
		prev = s;
	}
	return false;
 }

static const bool debug_dump_enum_tag_writes = false;
static const bool debug_dump_possible_reverse_initialization = false;

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

void TaggedUnionChecker::checkASTDecl(const TranslationUnitDecl *D, AnalysisManager &Mgr, BugReporter &BR) const {
	Finder.matchAST(Mgr.getASTContext());
}

#if 0
Case #1 - Enum access
- The field of a parent object is accessed.
- The parent object's type is a tagged union type.
- The accessed field is the enum field of said tagged union type.

Case #2 - Union access
- The field of a parent object is accessed.
- The parent object's is also parent of a grandparent object, whose type is a tagged union type.

Case #3 - Whole Union access (optional)
- The field of a parent object is accessed.
- The parent object's type is a tagged union type.
- The accessed field is the union field of said tagged union type.

struct tagged_union {
	enum { t1, t2 } tag;
	union {
		int f1;
		short f2;
	} data;
};

struct tagged_union tu1, tu2;
tu1.data = tu2.data;

struct EnumWrite {
	
};

struct UnionWrite {
	
};

struct UnionLoad {
	
};

struct TaggedUnionAccess  {
	enum {
		TaggedUnionAccessType_None,
		TaggedUnionAccessType_EnumWrite,
		TaggedUnionAccessType_UnionWrite,
		TaggedUnionAccessType_UnionLoad,
	} Type;

	union {
		EnumWrite EnumWrite;
		UnionWrite UnionWrite;
		UnionLoad UnionLoad;
	};

	TaggedUnionAccess() : Type(TaggedUnionAccessType_None) { };
	TaggedUnionAccess(EnumWrite EW) : Type(TaggedUnionAccessType_EnumWrite), EnumWrite(EW) { };
	TaggedUnionAccess(UnionWrite UW) : Type(TaggedUnionAccessType_UnionWrite), UnionWrite(UW) { };
	TaggedUnionAccess(UnionLoad UL) : Type(TaggedUnionAccessType_UnionLoad), UnionLoad(UL) { };
};

(TaggedUnionAccess Access) {
	switch (Access.Type) {
		case TaggedUnionAccessType_None: return;
		case TaggedUnionAccessType_EnumWrite: {

		} break;
		case TaggedUnionAccessType_UnionWrite: {

		} break;
		case TaggedUnionAccessType_UnionLoad: {

		} break;
	}
}
#endif

void TaggedUnionChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *Statement, CheckerContext &C) const {

	auto *region = Loc.getAsRegion();
	if (!region) return;

	auto *field_region = region->getAs<FieldRegion>();
	if (!field_region) return;

	const FieldRegion *super_fieldregion = nullptr;

	bool IsEnumLikeAccess = true;
	RecordObject CandidateTaggedUnion = getRecordDeclOfSuperRegion(field_region, C);
	if (!CandidateTaggedUnion.type_decl) {
		if (!field_region->getSuperRegion()) return;
		if (!field_region->getSuperRegion()->getAs<FieldRegion>()) return;
		super_fieldregion = field_region->getSuperRegion()->getAs<FieldRegion>();

		CandidateTaggedUnion = getRecordDeclOfSuperRegion(super_fieldregion, C);
		if (!CandidateTaggedUnion.type_decl) return;
		IsEnumLikeAccess = false;
	}

	// I. Check whether the accessed object is a tagged union
	TaggedUnionDecl T;
	bool IsTaggedUnion = false;
	for (const TaggedUnionDecl &D : MatchCallback.TaggedUnions) {
		if (D.root == CandidateTaggedUnion.type_decl) {
			T = D;
			IsTaggedUnion = true;
			break;
		}
	}
	if (!IsTaggedUnion) return;

	// The accessed field should be the tag field of the tagged union.
	// The tagged union could have additional fields as well, not just the tag.
	//
	// This section implements a heuristic to detect when the union part is
	// initialized before the tag:
	//
	// t.Union.field1 = 123;
	// t.Kind = kind1;
	//
	// Normally, the checker establishes pairs of (enum constant, union field)
	// upon union accesses, however, when the union is initialized first, the tag
	// value at the moment is outdated, because it is going to be provided
	// later "on the next line".
	//
	if (!IsLoad && IsEnumLikeAccess && field_region->getDecl() == T.enum_field_decl) {

		// This should be a CFGStmt, since checkLocation is load or store, right?
		const Stmt *access_stmt = C.getCFGElementRef()->getAs<clang::CFGStmt>()->getStmt();
		const BinaryOperator *assignment_stmt = llvm::dyn_cast<BinaryOperator>(access_stmt);
		if (!assignment_stmt) return;

		SVal new_enum_value = C.getSVal(assignment_stmt->getRHS());

		// Reverse iteration helps simplify the removal of items
		//
		for (int i = pendingUnionAccesses.size() - 1; 0 <= i; i -= 1) {
			auto &union_access = pendingUnionAccesses[i];
			const DynTypedNodeList parents = C.getAnalysisManager().getASTContext().getParents(*access_stmt);
			if (parents.size() == 1) {
				const CompoundStmt *compound_stmt = parents[0].get<CompoundStmt>();
				bool result = firstIsRightBeforeSecondInCompoundStmt(union_access.access_stmt, access_stmt, compound_stmt, C) && (union_access.which_tagged_union == CandidateTaggedUnion) && !union_access.IsLoad;
				if (!result) return;

				// A matching union assignment was found for this enum assignment.
				MemRegionManager &m = C.getStoreManager().getRegionManager();
				const FieldRegion *enum_field_region = m.getFieldRegion(T.enum_field_decl, CandidateTaggedUnion.region);
				union_access.tag_value_apsint = (new_enum_value.getAsInteger() ? std::optional{*new_enum_value.getAsInteger()} : std::optional<llvm::APSInt>{});
				updateTaggedUnionMappings(union_access);
				pendingUnionAccesses[i] = pendingUnionAccesses[pendingUnionAccesses.size()-1];
				pendingUnionAccesses.pop_back();
			}
		}
	} else if (super_fieldregion && super_fieldregion->getDecl() == T.union_field_decl) {

		// TODO: Is there a way to get the enum_field_region without calling getFieldRegion?
		MemRegionManager &m = C.getStoreManager().getRegionManager();
		const FieldRegion *enum_field_region = m.getFieldRegion(T.enum_field_decl, CandidateTaggedUnion.region);
		llvm::errs() << "asdfasdfasdf" << '\n';
		enum_field_region->dumpToStream(llvm::errs());
		llvm::errs() << '\n';

		QualType enum_type = enum_field_region->getValueType();
		SVal enum_sval = C.getState()->getSVal(enum_field_region, enum_type);
		// SVal enum_sval = C.getConstraintManager().getSymVal(C.getState(), );
		enum_sval.getAsSymbol()->dump(); llvm::errs() << '\n';
		const llvm::APSInt *apsint = enum_sval.getAsInteger();
		llvm::errs() << (apsint ? "yay" : "nay") << '\n';

		UnionAccess a;
		a.tag_value_apsint = (apsint ? std::optional{*apsint} : std::optional<llvm::APSInt>{});
		a.tagged_union_decl = T;
		a.which_tagged_union = CandidateTaggedUnion;
		a.IsLoad = IsLoad;
		a.accessed_union_field = field_region->getDecl();
		a.access_stmt = C.getCFGElementRef()->getAs<clang::CFGStmt>()->getStmt(); // Should be a CFGStmt, as checkLocation is load or store, right?
		pendingUnionAccesses.push_back(a);
	}
}

void TaggedUnionChecker::checkEndAnalysis(ExplodedGraph &G, BugReporter &BR, ExprEngine &Eng) const {
	for (auto &access : pendingUnionAccesses) {
		updateTaggedUnionMappings(access);
	}
}

void TaggedUnionChecker::checkEndOfTranslationUnit(const TranslationUnitDecl *TU, AnalysisManager& mgr, BugReporter &BR) const {
	for (auto &access : pendingUnionAccesses) {
		updateTaggedUnionMappings(access);
	}

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
			if (is_new_value || is_last_value) {
				if ((is_new_value ? i - first : i - first + 1) > 1) {
					auto &access = mappings[first];

					auto *ADC = mgr.getAnalysisDeclContext(TU);
					auto Report = std::make_unique<BasicBugReport>(BT, "This tagged union type is inconsistently used", PathDiagnosticLocation(access.which_tagged_union.type_decl, BR.getSourceManager()));
					Report->setDeclWithIssue(tagged_union_decl);

					for (vsize_t k = first; k < (is_new_value ? i : mappings.size()); k += 1) {
						const EnumConstantDecl *matched_decl;
						for (const EnumConstantDecl *Enumerator : mappings[k].tagged_union_decl.enum_decl->enumerators()) {
							if (llvm::APSInt::isSameValue(Enumerator->getInitVal(), *mappings[k].tag_value_apsint)) {
								matched_decl = Enumerator;
								break;
							}
						}
						PathDiagnosticLocation ELoc = PathDiagnosticLocation::createBegin(mappings[k].access_stmt, BR.getSourceManager(), ADC);
						const char Format[] = "Here '{0}' is matched with the union field '{1}'";
						std::string S = llvm::formatv(Format, matched_decl->getName(), mappings[k].accessed_union_field->getName());
						// Internally, a copy of S is stored in the note
						Report->addNote(S, ELoc);
					}

					BR.emitReport(std::move(Report));
				}
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
