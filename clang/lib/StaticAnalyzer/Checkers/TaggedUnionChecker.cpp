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

#include <map>

/*
 * Figyelmeztetések:
 * - Egy adott állandóval több adattagot is elérnek
 * - Nem használt állandó vagy unió adattag
 * - NONE vagy COUNT állandóval elérnek bármilyen adattagot
 * - Érvénytelen érték a tag mezőben (a megengedett értékeket ki lehet nyerni az AST-ből)
 *
 * A nem használtashoz viszont kellene egy olyan leképezés, hogy voltak-e használva
 * az egyes adattagok vagy állandók.
 * 
 * Lehet-e következtetni a hozzáfért unió adattagból az enum állandóra?
 *
 * Ha korábban volt olyan, hogy a tag1 hozzá volt rendelve a field1-hez és most
 * nem tudjuk, hogy mi a tag, de hozzáfértek a field1-hez, akkor elvárhatjuk-e azt,
 * hogy ilyenkor is a tag1 van érvényben? Ha egy unió adattaghoz több enum is 
 * tartozik, amire láttunk már példát, akkor így nem lehet következtetni.
 *
 * NoteTag
 *
 */

#if 0

Kitalálni

Egymásban lévő tagged union-ok

#endif

using namespace clang;
using namespace ento;

#if 0
REGISTER_MAP_WITH_PROGRAMSTATE(tagged_union_markers_tag,  const MemRegion*, llvm::APSInt)
REGISTER_MAP_WITH_PROGRAMSTATE(tagged_union_markers_data, const MemRegion*, const FieldDecl*)
#endif

namespace {

struct tagged_union_maps {
	std::map<llvm::APSInt, const FieldDecl*> invariants;
	std::map<const FieldDecl*, bool> field_usages;
	std::map<llvm::APSInt, bool> tag_usages;
};

class TaggedUnionChecker : public Checker<check::ASTDecl<TranslationUnitDecl>, check::BranchCondition, check::Location> {

	const BugType BT{this, "Inconsistent tagged union access!"};
    mutable std::map<const RecordDecl*, std::map<llvm::APSInt, const FieldDecl*>> tagged_union_invariants;
	mutable std::map<const RecordDecl*, std::map<llvm::APSInt, const FieldDecl*>> tagged_union_field_usages;

	// void checkEnumTagAssignment(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;
	void checkEnumTagAccess(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;

public:
	void checkBranchCondition(const clang::Stmt *Statement, CheckerContext &C) const;
	void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;
	void checkASTDecl(const TranslationUnitDecl *D, AnalysisManager &Mgr, BugReporter &BR) const;
	void checkASTCodeBody(const Decl *D, AnalysisManager &AM, BugReporter &B) const;
};
} // end anonymous namespace

#include <stdio.h>

#define GOTHERE GOTHEREM("")
#define GOTHEREM(message) printf("(%s:%i) %s\n", __FILE__, __LINE__, message)

class MyMatchCallback : public clang::ast_matchers::MatchFinder::MatchCallback {
	BugReporter &BR;
	AnalysisDeclContext *ADC;
	const Checker<check::ASTDecl<TranslationUnitDecl>, check::BranchCondition, check::Location> *C;

public:
	std::vector<const FieldDecl*> field_decls;
	llvm::SmallSet<llvm::APSInt, 32> enum_values;
	const FieldDecl *enum_field;
	const FieldDecl *union_field;

	virtual void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override;
	MyMatchCallback(BugReporter &Reporter, AnalysisDeclContext *Context, const Checker<check::ASTDecl<TranslationUnitDecl>, check::BranchCondition, check::Location> *C)
		: BR(Reporter), ADC(Context), C{C}, enum_field{nullptr}, union_field{nullptr} {}

	
};

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

std::size_t getNumberOfValidEnumValues(const EnumDecl *ED) {
	llvm::SmallSet<llvm::APSInt, 32> EnumValues;

	for (const auto Enumerator : ED->enumerators()) {
	  EnumValues.insert(Enumerator->getInitVal());
	}

	return EnumValues.size();
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

	this->enum_field = TagField;
	this->union_field = UnionField;

	const auto *UnionDef =
	    UnionField->getType().getCanonicalType().getTypePtr()->getAsRecordDecl();
	const auto *EnumDef = llvm::dyn_cast<EnumDecl>(
	    TagField->getType().getCanonicalType().getTypePtr()->getAsTagDecl());

	assert(UnionDef && "UnionDef is missing!");
	assert(EnumDef && "EnumDef is missing!");
	if (!UnionDef || !EnumDef)
	  return;

	for (const auto Enumerator : EnumDef->enumerators()) {
	  enum_values.insert(Enumerator->getInitVal());
	}

    for (const auto fd : UnionDef->fields()) {
		field_decls.push_back(fd);
	}

	const std::size_t UnionMemberCount = llvm::range_size(UnionDef->fields());
	const std::size_t TagCount = getNumberOfValidEnumValues(EnumDef);

	if (UnionMemberCount > TagCount) {
	  PathDiagnosticLocation ELoc = PathDiagnosticLocation::createBegin(Root, BR.getSourceManager(), ADC);

	  BR.EmitBasicReport(ADC->getDecl(), C, "Tagged union checker1", "Tagged union checker2", "Tagged union has more data members than tags!", ELoc);
	} 

}

static bool isInCondition(const Stmt *S, CheckerContext &C) {
  ParentMapContext &ParentCtx = C.getASTContext().getParentMapContext();
  bool CondFound = false;
  while (S && !CondFound) {
    const DynTypedNodeList Parents = ParentCtx.getParents(*S);
    if (Parents.empty())
      break;
    const auto *ParentS = Parents[0].get<Stmt>();
    if (!ParentS || isa<CallExpr>(ParentS))
      break;
    switch (ParentS->getStmtClass()) {
    case Expr::IfStmtClass:
      CondFound = (S == cast<IfStmt>(ParentS)->getCond());
      break;
    case Expr::ForStmtClass:
      CondFound = (S == cast<ForStmt>(ParentS)->getCond());
      break;
    case Expr::DoStmtClass:
      CondFound = (S == cast<DoStmt>(ParentS)->getCond());
      break;
    case Expr::WhileStmtClass:
      CondFound = (S == cast<WhileStmt>(ParentS)->getCond());
      break;
    case Expr::SwitchStmtClass:
      CondFound = (S == cast<SwitchStmt>(ParentS)->getCond());
      break;
    case Expr::ConditionalOperatorClass:
      CondFound = (S == cast<ConditionalOperator>(ParentS)->getCond());
      break;
    case Expr::BinaryConditionalOperatorClass:
      CondFound = (S == cast<BinaryConditionalOperator>(ParentS)->getCommon());
      break;
    default:
      break;
    }
    S = ParentS;
  }
  return CondFound;
}

void TaggedUnionChecker::checkBranchCondition(const clang::Stmt *Statement, CheckerContext &C) const {
	return;
	GOTHEREM("checkBranchCondition kezdés");

	const auto *BinaryOperator = llvm::dyn_cast_or_null<clang::BinaryOperator>(Statement);
	if (!BinaryOperator) return;
	GOTHEREM("BinaryOperator");

	const auto *Branch = llvm::dyn_cast_or_null<clang::IfStmt>(Statement);
	if (!Branch) return;

	const auto *Switch = llvm::dyn_cast_or_null<clang::SwitchStmt>(Statement);
	if (!Switch) return;
	GOTHERE;

	const auto *Condition = Switch->getCond();
	if (!Condition) return;
	GOTHERE;

	const auto *ConditionType = Condition->getType().getCanonicalType().getTypePtr();
	if (!ConditionType || !ConditionType->isEnumeralType()) return;
	GOTHERE;

	const auto *ConditionTypeDecl = ConditionType->getAsTagDecl();
	if (!ConditionTypeDecl) return;
	GOTHERE;

	const auto *EnumDefinition = llvm::dyn_cast_or_null<clang::EnumDecl>(ConditionTypeDecl->getDefinition());
	if (!EnumDefinition) return;
	GOTHERE;

	auto Report = std::make_unique<PathSensitiveBugReport>(BT, "Inconsistent tagged union access!", C.generateErrorNode());
	Report->addRange(Switch->getSourceRange());
	C.emitReport(std::move(Report));
}

#if 0

struct
	enum
	union
		struct
			struct 

#endif

#if 0
static void printParents(const Stmt *S, CheckerContext &C) {
  ParentMapContext &ParentCtx = C.getASTContext().getParentMapContext();
  while (S) {
    const DynTypedNodeList Parents = ParentCtx.getParents(*S);
    if (Parents.empty())
      break;
    const auto *ParentS = Parents[0].get<Stmt>();
    if (!ParentS || isa<CallExpr>(ParentS))
      break; 
	ParentS->dump();
	llvm::errs() << '\n';
    S = ParentS;
  }
}

static void ancestorsValami(const Stmt *S, CheckerContext &C) {
  ParentMapContext &ParentCtx = C.getASTContext().getParentMapContext();
  const Stmt *prev = nullptr;
  while (S) {
    const DynTypedNodeList Parents = ParentCtx.getParents(*S);
    if (Parents.empty())
      break;
    const auto *ParentS = Parents[0].get<Stmt>();
    if (!ParentS || isa<CallExpr>(ParentS))
      break; 
	switch (S->getStmtClass()) {
		case Expr::BinaryOperatorClass: {
			
		} break;
	}
	prev = S;
    S = ParentS;
  }
}
#endif

// void TaggedUnionChecker::checkEnumTagAssignment(SVal Loc, bool IsLoad, const Stmt *Statement, CheckerContext &C) const {
// 	
// }

void TaggedUnionChecker::checkEnumTagAccess(SVal Loc, bool IsLoad, const Stmt *Statement, CheckerContext &C) const {
	using namespace clang::ast_matchers;

	llvm::errs() << '\n';
	// Statement->dump();

	auto *region = Loc.getAsRegion();
	if (!region) return;

	// Is this a data field
	auto *field_region = region->getAs<FieldRegion>();
	if (!field_region) return;

	auto *super_fieldregion = field_region->getSuperRegion();
	auto *tvr = super_fieldregion->getAs<TypedValueRegion>();
	if (!tvr) return;

	QualType qualtype_desugared = tvr->getDesugaredValueType(C.getASTContext());
	const Type *desugared_type = qualtype_desugared.getTypePtrOrNull();
	if (!desugared_type) return;
	if (!desugared_type->isRecordType()) return;

	const RecordType *desugared_record_type = desugared_type->getAsStructureType();
	if (!desugared_record_type) return; 
	const RecordDecl *root = desugared_record_type->getDecl();

	AnalysisManager &Mgr = C.getAnalysisManager();
	MatchFinder Finder;
	MyMatchCallback CB(C.getBugReporter(), Mgr.getAnalysisDeclContext(root), this);
	  Finder.addMatcher(
	    recordDecl(
	        anyOf(isStruct(), isClass()),
	        has(fieldDecl(hasType(qualType(hasCanonicalType(recordType()))))
	                .bind("union")),
	        has(fieldDecl(hasType(qualType(hasCanonicalType(enumType()))))
	                .bind("tags")))
	        .bind("root"),
	    &CB);
	Finder.matchAST(Mgr.getASTContext());
	if (!CB.enum_field || !CB.union_field) return;

	MemRegionManager &memregion_manager = region->getMemRegionManager();
	const FieldRegion *union_field_region = memregion_manager.getFieldRegion(CB.union_field, tvr);
	const FieldRegion *enum_field_region = memregion_manager.getFieldRegion(CB.enum_field, tvr);

#if 0
  const NoteTag *constructSetEofNoteTag(CheckerContext &C, SymbolRef StreamSym) const {
    return C.getNoteTag([this, StreamSym](PathSensitiveBugReport &BR) {
      if (!BR.isInteresting(StreamSym) || &BR.getBugType() != this->getBT_StreamEof())
        return "";

      BR.markNotInteresting(StreamSym);

      return FeofNote;
    });
  }
#endif

	if (region->isSubRegionOf(enum_field_region) && !IsLoad) {
		SymbolRef s = nullptr;
		const NoteTag *first_access_of_field = C.getNoteTag([enum_field_region](PathSensitiveBugReport &BR) {
			return BR.isInteresting(enum_field_region) ? "Tag set to a new value!" : "";
		});
		C.addTransition(C.getState(), first_access_of_field);
	}

	return;

	const Expr *e = llvm::dyn_cast_or_null<Expr>(Statement);
	if (e) {
		llvm::errs() << "is expr\n";
		e = e->IgnoreImpCasts();
		// printParents(e, C);
	}

	ParentMapContext &ParentCtx = C.getASTContext().getParentMapContext();
    const DynTypedNodeList Parents = ParentCtx.getParents(*Statement);
	if (!Parents.empty()) {
		const auto *ParentExpression = Parents[0].get<Stmt>();
		if (ParentExpression) {
			llvm::errs() << ParentExpression->getStmtClassName() << '\n';
		} else {
			llvm::errs() << "Parent is not Stmt!\n";
		}
	} else {
		llvm::errs() << "Parents empty!\n";
	}

#if 0
	bool iic = isInCondition(Statement, C);
	llvm::errs() << "checkLocation is in condition: " << iic << '\n';
	llvm::errs() << Statement->getStmtClassName() << '\n';
	if (iic) {
		Statement->dump();
	}

	for (auto it = Statement->child_begin(); it != Statement->child_end(); it++) {
		it->dump();
	}
#endif

}

enum access_type {
	access_type_tag,
	access_type_union_field
};

void TaggedUnionChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *Statement, CheckerContext &C) const {
	using namespace clang::ast_matchers;
	checkEnumTagAccess(Loc, IsLoad, Statement, C);

	auto *region = Loc.getAsRegion();
	if (!region) return;

	// Is this a data field
	auto *field_region = region->getAs<FieldRegion>();
	if (!field_region) return;

	auto *super_fieldregion = field_region->getSuperRegion();
	auto *super_subregion = super_fieldregion->getAs<SubRegion>();
	if (!super_subregion) return;

	auto *super_super_subregion = super_subregion->getSuperRegion();
	if (!super_super_subregion) return;
	auto *tvr = super_super_subregion->getAs<TypedValueRegion>();
	if (!tvr) return;

	QualType qualtype_desugared = tvr->getDesugaredValueType(C.getASTContext());
	const Type *desugared_type = qualtype_desugared.getTypePtrOrNull();
	if (!desugared_type) return;
	if (!desugared_type->isRecordType()) return;

	const RecordType *desugared_record_type = desugared_type->getAsStructureType();
	if (!desugared_record_type) return;
	const RecordDecl *root = desugared_record_type->getDecl();

	AnalysisManager &Mgr = C.getAnalysisManager();
	MatchFinder Finder;
	MyMatchCallback CB(C.getBugReporter(), Mgr.getAnalysisDeclContext(root), this);
	  Finder.addMatcher(
	    recordDecl(
	        anyOf(isStruct(), isClass()),
	        has(fieldDecl(hasType(qualType(hasCanonicalType(recordType()))))
	                .bind("union")),
	        has(fieldDecl(hasType(qualType(hasCanonicalType(enumType()))))
	                .bind("tags")))
	        .bind("root"),
	    &CB);	
	Finder.matchAST(Mgr.getASTContext());
	if (!CB.enum_field || !CB.union_field) return;

	MemRegionManager &memregion_manager = region->getMemRegionManager();
	const FieldRegion *union_field_region = memregion_manager.getFieldRegion(CB.union_field, tvr);
	const FieldRegion *enum_field_region = memregion_manager.getFieldRegion(CB.enum_field, tvr);

	const ProgramStateRef &programstate = C.getState();
	QualType enum_type = enum_field_region->getValueType();
	SVal enum_value_sval = programstate->getSVal(enum_field_region, enum_type);

    const llvm::APSInt *tag_value_apsint = enum_value_sval.getAsInteger();
	const FieldDecl *accessed_union_field = nullptr;
	const FieldRegion *accessed_union_field_region = nullptr;
	for (auto decl : CB.field_decls) {
		const FieldRegion *decl_region = memregion_manager.getFieldRegion(decl, union_field_region);
		if (region->isSubRegionOf(decl_region)) {
			accessed_union_field = decl;
			accessed_union_field_region = decl_region;
		}
	}

	if (tag_value_apsint) {
		if (accessed_union_field) {
			auto &map_for_current = tagged_union_invariants[root];
			auto expected_field = map_for_current.find(*tag_value_apsint);
			if (expected_field != map_for_current.end()) {
				if (accessed_union_field != expected_field->second) {
					ExplodedNode *N = C.generateErrorNode();
					auto Report = std::make_unique<PathSensitiveBugReport>(BT, BT.getCategory(), N);
					Report->markInteresting(union_field_region);
					Report->markInteresting(enum_field_region);
					bugreporter::trackStoredValue(Loc, accessed_union_field_region, *Report);
					C.emitReport(std::move(Report));
				}
			} else {
				map_for_current.emplace(*tag_value_apsint, accessed_union_field);
				const NoteTag *first_access_of_field = C.getNoteTag([enum_field_region](PathSensitiveBugReport &BR) {
			return BR.isInteresting(enum_field_region) ? "First access of field!" : "";
		});
				C.addTransition(C.getState(), first_access_of_field);
			}
		}
	}
}

void TaggedUnionChecker::checkASTDecl(const TranslationUnitDecl *D, AnalysisManager &Mgr, BugReporter &BR) const {
	using namespace clang::ast_matchers;

	MatchFinder Finder;
	MyMatchCallback CB(BR, Mgr.getAnalysisDeclContext(D), this);
	  Finder.addMatcher(
	    recordDecl(
	        anyOf(isStruct(), isClass()),
	        has(fieldDecl(hasType(qualType(hasCanonicalType(recordType()))))
	                .bind("union")),
	        has(fieldDecl(hasType(qualType(hasCanonicalType(enumType()))))
	                .bind("tags")))
	        .bind("root"),
	    &CB);	
	Finder.matchAST(Mgr.getASTContext());
}

void ento::registerTaggedUnionChecker(CheckerManager &Mgr) {
	Mgr.registerChecker<TaggedUnionChecker>();
}

bool ento::shouldRegisterTaggedUnionChecker(const CheckerManager &mgr) {
	return true;
}
