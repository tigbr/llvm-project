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

class TaggedUnionChecker;

class MyMatchCallback : public clang::ast_matchers::MatchFinder::MatchCallback {
	BugReporter *BR;
	AnalysisDeclContext *ADC;
	const TaggedUnionChecker * const C;

public:
	std::vector<const FieldDecl*> field_decls;
	llvm::SmallSet<llvm::APSInt, 32> enum_values;

	const FieldDecl *enum_field;
	const FieldDecl *union_field;

    void initialize(BugReporter *Reporter, AnalysisDeclContext *Context);
	virtual void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override;
	MyMatchCallback(const TaggedUnionChecker * const Checker)
		: BR{nullptr}, ADC{nullptr}, C{Checker}, enum_field{nullptr}, union_field{nullptr} {}
};

struct PendingTaggedUnionAccess {
	ExplodedNode *exploded_node;
	CheckerContext checker_context;
	// ConstCFGElementRef access_stmt;
	const RecordDecl *tagged_union_decl;
	const FieldDecl *accessed_union_field;
	SVal tag_sval;
};

class TaggedUnionChecker : public Checker<check::ASTDecl<TranslationUnitDecl>, check::PostStmt<DeclRefExpr>, check::PostStmt<BinaryOperator>, check::BranchCondition, check::Location, check::EndAnalysis> {

	const BugType BT{this, "Inconsistent tagged union access!"};
    mutable std::map<const RecordDecl*, std::map<llvm::APSInt, const FieldDecl*>> tagged_union_invariants;
	mutable std::map<const RecordDecl*, std::map<llvm::APSInt, const FieldDecl*>> tagged_union_field_usages;
	mutable std::vector<PendingTaggedUnionAccess> contexts;

	// void checkEnumTagAssignment(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;
	void checkEnumTagAccess(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;
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
 
	void checkBranchCondition(const clang::Stmt *Statement, CheckerContext &C) const;
	void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;
	void checkLocation2(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;
    void checkPostStmt(const BinaryOperator *O, CheckerContext &C) const;
    void checkPostStmt(const DeclRefExpr *D, CheckerContext &C) const;
	void checkASTDecl(const TranslationUnitDecl *D, AnalysisManager &Mgr, BugReporter &BR) const;
	void checkASTCodeBody(const Decl *D, AnalysisManager &AM, BugReporter &B) const;
	void checkEndAnalysis(ExplodedGraph &G, BugReporter &BR, ExprEngine &Eng) const;
};
} // end anonymous namespace

#include <stdio.h>

#define GOTHERE GOTHEREM("")
#define GOTHEREM(message) printf("(%s:%i) %s\n", __FILE__, __LINE__, message)

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

void MyMatchCallback::initialize(BugReporter *Reporter, AnalysisDeclContext *Context) {
	this->BR = Reporter;
	this->ADC = Context;
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
	  PathDiagnosticLocation ELoc = PathDiagnosticLocation::createBegin(Root, BR->getSourceManager(), ADC);

	  BR->EmitBasicReport(ADC->getDecl(), C, "Tagged union checker1", "Tagged union checker2", "Tagged union has more data members than tags!", ELoc);
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


/*
 * DeclRefExpr nem feltétlenül egy közevtlen union adattagra hivatkozik:
 *
 * foo.bar.tagged_union.data.field1.a.b.c.d = 7;
 *
 */
void TaggedUnionChecker::checkPostStmt(const DeclRefExpr *D, CheckerContext &C) const {
	if (const FieldDecl *d = llvm::dyn_cast<FieldDecl>(D->getDecl())) {
		d->getParent() -> isUnion();
	}
}

void TaggedUnionChecker::checkPostStmt(const BinaryOperator *O, CheckerContext &C) const {
	if (O->getOpcode() == BO_Assign) {
		
	}
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
	bool IsStore = !IsLoad;
	using namespace clang::ast_matchers;

	// llvm::errs() << '\n';
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
	MatchCallback.initialize(&C.getBugReporter(), Mgr.getAnalysisDeclContext(root));
	Finder.matchAST(Mgr.getASTContext());
	if (!MatchCallback.enum_field || !MatchCallback.union_field) return;

	MemRegionManager &memregion_manager = region->getMemRegionManager();
	const FieldRegion *union_field_region = memregion_manager.getFieldRegion(MatchCallback.union_field, tvr);
	const FieldRegion *enum_field_region = memregion_manager.getFieldRegion(MatchCallback.enum_field, tvr);

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

	if (region->isSubRegionOf(enum_field_region) && IsStore) {
		SymbolRef s = nullptr;
		const NoteTag *first_access_of_field = C.getNoteTag([enum_field_region](PathSensitiveBugReport &BR) {
			return "The tag field of this tagged union is changed here";
		});
		ExplodedNode *en_tag = C.addTransition(C.getState(), first_access_of_field);
		for (int i = 0; i < contexts.size(); i += 1) {
			if (contexts[i].tagged_union_decl == root) {
			// if (contexts[i].) {

			// }
			}
			// ExplodedNode *en_union = contexts[i].exploded_node;
			// if (en_union->) {
			// 	
			// }
		}
	}
}

static std::vector<std::string> report_messages;

static bool process_tagged_union(const RecordDecl *R, const FieldDecl **out_enum, const FieldDecl **out_union) {
    bool has_union = false;
    bool has_enum = false;
	for (auto decl : R->fields()) {
        if (has_union && true) return false;
        if (has_enum && true)  return false;
	}
    return true;
}


void TaggedUnionChecker::checkLocation2(SVal Loc, bool IsLoad, const Stmt *Statement, CheckerContext &C) const {
    auto *region = Loc.getAsRegion();
	if (!region) return;

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

    const FieldDecl *union_field = nullptr;
    const FieldDecl *enum_field = nullptr;
    if (!process_tagged_union(root, &enum_field, &union_field)) return;

	const RecordDecl *union_decl = llvm::dyn_cast<RecordType>(union_field->getType())->getDecl();
    auto *accessed_field_decl = field_region->getDecl();
    for (auto field : union_decl->fields()) {
		if (field == accessed_field_decl) {
			MemRegionManager &memregion_manager = region->getMemRegionManager();
			const FieldRegion *enum_field_region = memregion_manager.getFieldRegion(enum_field, tvr);
			QualType enum_type = enum_field_region->getValueType();
			SVal enum_value_sval = C.getState()->getSVal(enum_field_region, enum_type);
    		const llvm::APSInt *tag_value_apsint = enum_value_sval.getAsInteger();
       }
    }
}

#define KindCase(kind_name) case kind_name: msg = #kind_name; break;

const Stmt* CFGElementToStmt(CFGElement element) {
	if (element.getKind() == clang::CFGElement::Kind::Statement)
		if (auto cfgstmt = element.getAs<CFGStmt>())
			return cfgstmt->getStmt();
	return nullptr;
}

static void asdf(SVal Loc, bool IsLoad, const Stmt *Statement, CheckerContext &C) {
	const LocationContext *Location = C.getLocationContext();
	if (!Location) return;
    llvm::errs() << "Got LocationContext!\n";

	CFG *cfg = Location->getCFG();
	if (!cfg) return;
    llvm::errs() << "Got CFG!\n";
	llvm::errs() << "CFG size: " << cfg->size() << '\n';
    cfg->dump(C.getLangOpts(), true);
	return;

	for (CFGBlock *block : cfg->nodes()) {
		for (unsigned i = 0; i < block->size(); i += 1) {
			CFGElement element = (*block)[i];
			if (const Stmt *stmt = CFGElementToStmt(element)) {
				if (stmt == Statement) {
					if (i != (~(unsigned)0) && i + 1 < block->size()) {
						if (const Stmt *stmt2 = CFGElementToStmt((*block)[i+1])) {
							if (dyn_cast<CStyleCastExpr>(stmt2)) { 
								Statement->dump();
							}
						}
					}
				}
			}
		}
	}
}

#if 0
------------ Source ------------
T.field_A = 5;
T.tag = tag_A;

------------ CFG ------------
T
T.field_A
5
T.field_A = 5; <--- CheckLocation: SVal Loc: &T.field_A. Statement: .field_A gyökérkifejezése (MemberExpr)
T
T.tag
tag_A
T.tag = tag_A;

ExplodedNode X: union field A assigned in tagged union object T1 of type TU1
ExplodedNode Y: enum field B assigned in tagged union object T2 of type TU2

I.   Is T1 the same object as T2?
II.  Is TU1 the same type as TU2?
III. Is X and Y on the same path of execution?
IV.  Is Y "essentially right after" X?

Possible solution for IV:

* The two assignment operations should be right after each other in the AST
* ASTContext: getParents method -> finding common parent compoundStmt
* Iterating compoundStmt to see if they are after each other

On union access save:
* result of getCFGElementRef()
* const RecordDecl * of the accessed tagged union
* 
#endif

static void asdf2(SVal Loc, bool IsLoad, const Stmt *Statement, CheckerContext &C) {
	auto cfgelement = C.getCFGElementRef();
	if (auto cfgstmt = cfgelement->getAs<clang::CFGStmt>()) {
		cfgstmt->getStmt()->dump();
		// Loc.dump();
		// llvm::errs() << '\n';
		// Statement->dump();
	}
}

static void asdf3(SVal Loc, bool IsLoad, const Stmt *Statement, CheckerContext &C) {
}

void TaggedUnionChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *Statement, CheckerContext &C) const {
	using namespace clang::ast_matchers;
	asdf2(Loc, IsLoad, Statement, C);

	// Statement->dump();

	// const NoteTag *note_something = C.getNoteTag([](PathSensitiveBugReport &BR) { return "Something!"; });
	// C.addTransition(C.getState(), note_something);

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
	MatchCallback.initialize(&C.getBugReporter(), Mgr.getAnalysisDeclContext(root));
	Finder.matchAST(Mgr.getASTContext());
	if (!MatchCallback.enum_field || !MatchCallback.union_field) return;

	MemRegionManager &memregion_manager = region->getMemRegionManager();
	const FieldRegion *union_field_region = memregion_manager.getFieldRegion(MatchCallback.union_field, tvr);
	const FieldRegion *enum_field_region = memregion_manager.getFieldRegion(MatchCallback.enum_field, tvr);

	const ProgramStateRef &programstate = C.getState();
	QualType enum_type = enum_field_region->getValueType();
	SVal enum_value_sval = programstate->getSVal(enum_field_region, enum_type);

    const llvm::APSInt *tag_value_apsint = enum_value_sval.getAsInteger();
	const FieldDecl *accessed_union_field = nullptr;
	const FieldRegion *accessed_union_field_region = nullptr;
	for (auto decl : MatchCallback.field_decls) {
		const FieldRegion *decl_region = memregion_manager.getFieldRegion(decl, union_field_region);
		if (region->isSubRegionOf(decl_region)) {
			accessed_union_field = decl;
			accessed_union_field_region = decl_region;
		}
	}

	// for (auto& it = contexts.begin(); it != contexts.end(); it++) {
	// 	if (it.checker_context.getPredecessor()) {
	// 		
	// 	}
	// }

	for (int i = 0; i < contexts.size(); i += 1) {
		if (contexts[i].exploded_node == C.getPredecessor()) {
			C.addTransition();
			SVal enum_value_sval_after_transition = programstate->getSVal(enum_field_region, enum_type);
			const llvm::APSInt *tag_value_apsint_after_transition = enum_value_sval_after_transition.getAsInteger();
			if (tag_value_apsint_after_transition) {
				llvm::errs() << "Is the enum equal to " << *tag_value_apsint_after_transition << "?\n";
			}
			ExplodedNode *N = C.generateErrorNode();
			report_messages.push_back("asdfasdfasdfadsfadsf");
			std::string *new_message = &report_messages[report_messages.size() - 1];
			auto Report = std::make_unique<PathSensitiveBugReport>(BT, *new_message, N);
			C.emitReport(std::move(Report));
		}
	}

	if (accessed_union_field) {
		contexts.emplace_back(PendingTaggedUnionAccess{C.addTransition(), C, root, accessed_union_field, enum_value_sval});
	}

	return;

	if (accessed_union_field) {
		if (tag_value_apsint) {
			auto &map_for_current = tagged_union_invariants[root];
			auto expected_field = map_for_current.find(*tag_value_apsint);
			if (contexts.size() < 5) {
				contexts.emplace_back(PendingTaggedUnionAccess{C.addTransition(), C, root, accessed_union_field, enum_value_sval});
			}
			if (expected_field != map_for_current.end()) {
				if (accessed_union_field != expected_field->second) {
					ExplodedNode *N = C.generateErrorNode();

					EnumDecl *enum_declaration = llvm::dyn_cast<EnumDecl>(MatchCallback.enum_field->getType().getCanonicalType().getTypePtr()->getAsTagDecl());
					const EnumConstantDecl *matched_decl;
					for (const EnumConstantDecl *Enumerator : enum_declaration->enumerators()) {
						if (Enumerator->getInitVal() == *tag_value_apsint) {
							matched_decl = Enumerator;
							break;
						}
					}

                    report_messages.push_back("The '");
					std::string *new_message = &report_messages[report_messages.size() - 1];
					new_message->append(matched_decl->getName());
					new_message->append("' enum constant is used to access the '");
					new_message->append(accessed_union_field->getName());
					new_message->append("' union member, when previously it accessed '");
					new_message->append(expected_field->second->getName());
					new_message->append("' in this tagged union");

					auto Report = std::make_unique<PathSensitiveBugReport>(BT, *new_message, N);
					Report->markInteresting(union_field_region);
					Report->markInteresting(enum_field_region);
					bugreporter::trackStoredValue(Loc, accessed_union_field_region, *Report);
					C.emitReport(std::move(Report));
				}
			} else {
				map_for_current.emplace(*tag_value_apsint, accessed_union_field);
				ExplodedNode *N = C.generateErrorNode();

				EnumDecl *enum_declaration = llvm::dyn_cast<EnumDecl>(MatchCallback.enum_field->getType().getCanonicalType().getTypePtr()->getAsTagDecl());
				const EnumConstantDecl *matched_decl;
				for (const EnumConstantDecl *Enumerator : enum_declaration->enumerators()) {
					if (Enumerator->getInitVal() == *tag_value_apsint) {
						matched_decl = Enumerator;
						break;
					}
				}
				report_messages.push_back("");
				std::string *new_message = &report_messages[report_messages.size() - 1];
				new_message->append(matched_decl->getName());
				new_message->append(" is matched with the union field called '");
				new_message->append(accessed_union_field->getName());
				new_message->append("' in this tagged union");

				auto Report = std::make_unique<PathSensitiveBugReport>(BT, *new_message, N);
				Report->markInteresting(union_field_region);
				Report->markInteresting(enum_field_region);
				bugreporter::trackStoredValue(Loc, accessed_union_field_region, *Report);
				const NoteTag *first_access_of_field = C.getNoteTag([enum_field_region](PathSensitiveBugReport &BR) {
					return "First access of field!";
				});
				C.addTransition(C.getState(), first_access_of_field);
				C.emitReport(std::move(Report));
			}
		}
	}
}

void TaggedUnionChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &B) const {
    return;
	if (!D) return;
    llvm::errs() << "got TranslationUnitDecl!\n";
	CFG *cfg = Mgr.getCFG(D);
    if (!cfg) return; 
    llvm::errs() << "got CFG!\n";
    for (CFGBlock *block : cfg->nodes()) {
		for (unsigned i = 0; i < block->size(); i += 1) {
			CFGElement element = (*block)[i];
			const char *msg = nullptr;
            switch (element.getKind()) {
                default: msg = ""; break;
				KindCase(clang::CFGElement::Kind::Initializer)
				KindCase(clang::CFGElement::Kind::ScopeBegin)
				KindCase(clang::CFGElement::Kind::ScopeEnd)
				KindCase(clang::CFGElement::Kind::NewAllocator)
				KindCase(clang::CFGElement::Kind::LifetimeEnds)
				KindCase(clang::CFGElement::Kind::LoopExit)
				KindCase(clang::CFGElement::Kind::Statement)
				KindCase(clang::CFGElement::Kind::Constructor)
				KindCase(clang::CFGElement::Kind::CXXRecordTypedCall)
				KindCase(clang::CFGElement::Kind::AutomaticObjectDtor)
				KindCase(clang::CFGElement::Kind::DeleteDtor)
				KindCase(clang::CFGElement::Kind::BaseDtor)
				KindCase(clang::CFGElement::Kind::MemberDtor)
				KindCase(clang::CFGElement::Kind::TemporaryDtor)
				KindCase(clang::CFGElement::Kind::CleanupFunction)
			}
			llvm::errs() << msg << '\n';
		}
    }
}

void TaggedUnionChecker::checkASTDecl(const TranslationUnitDecl *D, AnalysisManager &Mgr, BugReporter &BR) const {
    MatchCallback.initialize(&BR, Mgr.getAnalysisDeclContext(D));
	Finder.matchAST(Mgr.getASTContext());
}

void TaggedUnionChecker::checkEndAnalysis(ExplodedGraph &G, BugReporter &BR, ExprEngine &Eng) const {
	return;
	for (int i = 0; i < contexts.size(); i += 1) {
		llvm::errs() << "CFG -> CFGBlocks -> CFGElements\n";
		CFG &cfg = contexts[i].exploded_node->getCFG();
		size_t idx = 0;
		for (CFGBlock *block : cfg) {
			if (idx == 1) {
				llvm::errs() << "getCFGBlock() is the same as second CFGBlock: " << (block == contexts[i].exploded_node->getCFGBlock()) << "\n";
			}
			llvm::errs() << "CFGBlock: " << idx << "\n";
			for (size_t j = 0; j < block->size(); j += 1) {
				CFGElement e = (*block)[j];
				if (e.getAs<CFGStmt>()) e.dump();
			}
			idx += 1;
		}
		llvm::errs() << "\n";
		llvm::errs() << "getCFGBlock() -> CFGElements\n";
		const CFGBlock *block = contexts[i].exploded_node->getCFGBlock();
		for (size_t j = 0; j < block->size(); j += 1) {
			CFGElement e = (*block)[j];
			if (e.getAs<CFGStmt>()) e.dump();
		}
		llvm::errs() << "\n\n";
	}
	return;
	for (int i = 0; i < contexts.size(); i += 1) {
		if (const ExplodedNode *exploded_node = contexts[i].exploded_node) 
		if (const Stmt *statement = exploded_node->getNextStmtForDiagnostics()) {
			statement->dump();
		}
	}
}

void ento::registerTaggedUnionChecker(CheckerManager &Mgr) {
	Mgr.registerChecker<TaggedUnionChecker>();
}

bool ento::shouldRegisterTaggedUnionChecker(const CheckerManager &mgr) {
	return true;
}

