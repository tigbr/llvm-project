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

namespace {

struct TaggedUnion {
	const RecordDecl *root;
	const RecordDecl *union_decl;
	const FieldDecl *union_field_decl;
	const EnumDecl *enum_decl;
	const FieldDecl *enum_field_decl;
};

struct TaggedUnionId {
	const RecordDecl *decl = nullptr;
	const TypedValueRegion *region = nullptr;
};

bool operator==(TaggedUnionId &a, TaggedUnionId &b) {
	return a.decl == b.decl && a.region == b.region;
}

struct EnumStore {
	TaggedUnionId which_tagged_union;
	const FieldDecl *field = nullptr;
	SVal new_tag_value;
};

struct UnionAccess {
	TaggedUnionId which_tagged_union;
	bool IsLoad;
	SVal tag_value;
	const FieldDecl *accessed_union_field = nullptr;
	const MemRegion *accessed_union_field_region = nullptr;
	ExplodedNode *exploded_node;
	const Stmt *access_stmt;
	PathSensitiveBugReport *report;
};

class TaggedUnionChecker;

class MyMatchCallback : public clang::ast_matchers::MatchFinder::MatchCallback {
	BugReporter *BR;
	AnalysisDeclContext *ADC;
	const TaggedUnionChecker * const C;

public:
	std::vector<TaggedUnion> TaggedUnions;

	bool AnalyzeTaggedUnions;

	std::vector<const FieldDecl*> field_decls;
	llvm::SmallSet<llvm::APSInt, 32> enum_values;

	const FieldDecl *enum_field;
	const FieldDecl *union_field;

    void initialize(BugReporter *Reporter, AnalysisDeclContext *Context);
	virtual void run(const clang::ast_matchers::MatchFinder::MatchResult &Result) override;
	MyMatchCallback(const TaggedUnionChecker * const Checker)
		: BR{nullptr}, ADC{nullptr}, C{Checker}, AnalyzeTaggedUnions{false}, enum_field{nullptr}, union_field{nullptr} {}
};

class TaggedUnionChecker : public Checker<check::ASTDecl<TranslationUnitDecl>, check::Location> {

	const BugType BT{this, "Inconsistent tagged union access!"};
    mutable std::map<const RecordDecl*, std::map<llvm::APSInt, const FieldDecl*>> tagged_union_invariants;
	mutable std::map<const RecordDecl*, std::map<llvm::APSInt, const FieldDecl*>> tagged_union_field_usages;
	mutable std::vector<UnionAccess> pendingUnionAccesses;

	// void checkEnumTagAssignment(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;

	void processUnionAccess(const UnionAccess&,TaggedUnion &T, CheckerContext &C) const;
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
 
	void checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const;
	void checkASTDecl(const TranslationUnitDecl *D, AnalysisManager &Mgr, BugReporter &BR) const;
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

	TaggedUnion t;
	t.root = Root;
	t.union_decl = UnionDef;
	t.union_field_decl = UnionField;
	t.enum_decl = EnumDef;
	t.enum_field_decl = TagField;
	this->TaggedUnions.push_back(t);
	if (!this->AnalyzeTaggedUnions) return;

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
	Finder.matchAST(Mgr.getASTContext()); // Is it possible to match this on a smaller AST?
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
		const NoteTag *first_access_of_field = C.getNoteTag([enum_field_region](PathSensitiveBugReport &BR) {
			return "The tag field of this tagged union is changed here";
		});
		C.addTransition(C.getState(), first_access_of_field);
	}
}

static std::vector<std::string> report_messages;

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

Solution for I.: Save the Memregion of the tagged union as a whole for both enum and union accesses
Solution for II.: Save Tagged Union RecordDecl for both enum and union accesses
Solution for III.: Either X must be the descendant of Y or Y must be the descendant of X in the exploded graph
Solution for IV:

* The two assignment operations should be right after each other in the AST
* ASTContext: getParents method -> finding common parent compoundStmt
* Iterating compoundStmt to see if they are after each other

On union access save:
* result of getCFGElementRef()
* const RecordDecl * of the accessed tagged union
* 
#endif

TaggedUnionId getRecordDeclOfSuperRegion(const FieldRegion *field_region, CheckerContext &C) {
	TaggedUnionId result;

	auto *super_field_region = field_region->getSuperRegion();
	result.region = super_field_region->getAs<TypedValueRegion>();
	if (!result.region) return result;

	QualType qualtype_desugared = result.region->getDesugaredValueType(C.getASTContext());
	const Type *desugared_type = qualtype_desugared.getTypePtrOrNull();
	if (!desugared_type) return result;
	if (!desugared_type->isRecordType()) return result;

	const RecordType *desugared_record_type = desugared_type->getAsStructureType();
	if (!desugared_record_type) return result; 
	result.decl = desugared_record_type->getDecl();

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

#if 0
void TaggedUnionChecker::pairTagAccessWithPendingUnionAccess(const TaggedUnionId id, CheckerContext &C) const {
	if (auto *cfgstmt = C.getCFGElementRef()->getAs<clang::CFGStmt>()) {
		if (UnionAccess.access_stmt_parent_compound_stmt) {
			for (auto &UnionAccess : pendingUnionAccesses) {
				bool result = firstIsAfterSecondInCompoundStmt(UnionAccess.access_stmt, cfgstmt, UnionAccess.access_stmt_parent_compound_stmt);
				if (result) {
					result &&= UnionAccess.tagged_union_decl == access.tagged_union_decl;
				}
				if (result) {
					result &&= UnionAccess.tagged_union_memregion == access.tagged_union_memregion;
				}
			}
		}
	}
	// TODO: Implement
	
}

void TaggedUnionChecker::saveUnionFieldAccess(const TaggedUnionAccess &access, CheckerContext &C) const {
	auto cfgelement = C.getCFGElementRef();
	if (auto cfgstmt = cfgelement->getAs<clang::CFGStmt>()) {
		const DynTypedNodeList parents = C.getAnalysisManager().getASTContext().getParents(*cfgstmt->getStmt());
		if (parents.size() == 1) {
			if (const CompoundStmt *compoundstmt = parents[0].get<CompoundStmt>()) {
				PendingTaggedUnionAccess pending{
					C.addTransition(),
						compoundstmt,
						cfgstmt->getStmt(),
						C,
						access.tagged_union_decl,
						access.accessed_union_field,
						access.tag_value_sval,
				};
				pendingUnionAccesses.emplace_back(pending);
			}
		}
	}
}
#endif

static const bool debug_dump_candidate_tagged_union = false;
static const bool debug_dump_union_field_accesses = false;
static const bool debug_peek_ahead_for_immediate_enum_tag_access = false;
static const bool debug_dump_enum_tag_writes = false;
static const bool debug_dump_possible_reverse_initialization = true;

void TaggedUnionChecker::processUnionAccess(const UnionAccess &a, TaggedUnion &T, CheckerContext &C) const {
	if (a.tag_value.getAsInteger() && a.accessed_union_field) {
					auto &map_for_current = tagged_union_invariants[a.which_tagged_union.decl];
					auto expected_field = map_for_current.find(*a.tag_value.getAsInteger());
					if (expected_field != map_for_current.end()) {
						if (a.accessed_union_field != expected_field->second) {
							ExplodedNode *N = C.generateNonFatalErrorNode();

							EnumDecl *enum_declaration = llvm::dyn_cast<EnumDecl>(T.enum_field_decl->getType().getCanonicalType().getTypePtr()->getAsTagDecl());
							const EnumConstantDecl *matched_decl = nullptr;
							for (const EnumConstantDecl *Enumerator : enum_declaration->enumerators()) {
								if (Enumerator->getInitVal().isRepresentableByInt64() && a.tag_value.getAsInteger()->isRepresentableByInt64() && Enumerator->getInitVal().getExtValue() == a.tag_value.getAsInteger()->getExtValue()) {
									matched_decl = Enumerator;
									break;
								}
							}

							report_messages.push_back("The '");
							std::string *new_message = &report_messages[report_messages.size() - 1];
							new_message->append(matched_decl->getName());
							new_message->append("' enum constant is used to access the '");
							new_message->append(a.accessed_union_field->getName());
							new_message->append("' union member, when previously it accessed '");
							new_message->append(expected_field->second->getName());
							new_message->append("' in this tagged union");

							auto Report = std::make_unique<PathSensitiveBugReport>(BT, *new_message, N);
							Report->markInteresting(union_field_region);
							Report->markInteresting(enum_field_region);
							bugreporter::trackStoredValue(Loc, union_field_region, *Report);
							C.emitReport(std::move(Report));
						}
					} else {
						map_for_current.emplace(*a.tag_value.getAsInteger(), a.accessed_union_field);
						ExplodedNode *N = C.generateNonFatalErrorNode();

						EnumDecl *enum_declaration = llvm::dyn_cast<EnumDecl>(T.enum_field_decl->getType().getCanonicalType().getTypePtr()->getAsTagDecl());
						const EnumConstantDecl *matched_decl;
						for (const EnumConstantDecl *Enumerator : enum_declaration->enumerators()) {
							if (Enumerator->getInitVal().isRepresentableByInt64() && a.tag_value.getAsInteger()->isRepresentableByInt64() && Enumerator->getInitVal().getExtValue() == a.tag_value.getAsInteger()->getExtValue()) {
								matched_decl = Enumerator;
								break;
							}
						}
						report_messages.push_back("");
						std::string *new_message = &report_messages[report_messages.size() - 1];
						new_message->append(matched_decl->getName());
						new_message->append(" is matched with the union field called '");
						new_message->append(a.accessed_union_field->getName());
						new_message->append("' in this tagged union");

						auto Report = std::make_unique<PathSensitiveBugReport>(BT, *new_message, N);
						Report->markInteresting(union_field_region);
						Report->markInteresting(enum_field_region);
						bugreporter::trackStoredValue(Loc, union_field_region, *Report);
						const NoteTag *first_access_of_field = C.getNoteTag([enum_field_region](PathSensitiveBugReport &BR) {
								return "First access of field!";
								});
						C.addTransition(C.getState(), first_access_of_field);
						C.emitReport(std::move(Report));
					}
				}
}

void TaggedUnionChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *Statement, CheckerContext &C) const {

	auto *region = Loc.getAsRegion();
	if (!region) return;

	auto *field_region = region->getAs<FieldRegion>();
	if (!field_region) return;

	const FieldRegion *super_fieldregion = nullptr;

	bool IsEnumLikeAccess = true;
	TaggedUnionId tagged_union_candidate = getRecordDeclOfSuperRegion(field_region, C);
	if (tagged_union_candidate.decl) {
		// llvm::errs() << "Potential enum access\n";
	} else {
		if (!field_region->getSuperRegion()) return;
		if (!field_region->getSuperRegion()->getAs<FieldRegion>()) return;
		super_fieldregion = field_region->getSuperRegion()->getAs<FieldRegion>();

		tagged_union_candidate = getRecordDeclOfSuperRegion(super_fieldregion, C);
		if (tagged_union_candidate.decl) {
			// llvm::errs() << "Potential union access\n";
			IsEnumLikeAccess = false;
		} else {
			return;
		}
	}

	for (auto &T : MatchCallback.TaggedUnions) {
		if (T.root == tagged_union_candidate.decl) {
			if (debug_dump_candidate_tagged_union) {
				llvm::errs() << "Candidate is a tagged union!\n";
				tagged_union_candidate.decl->dump();
			}
			// The accessed field should the tag field of the tagged union.
			// The tagged union could have additional fields as well, not just the tag.
			if (IsEnumLikeAccess && field_region->getDecl() == T.enum_field_decl) {
				if (!IsLoad) {
 					// This should be a CFGStmt, since checkLocation is load or store, right?
					const Stmt *access_stmt = C.getCFGElementRef()->getAs<clang::CFGStmt>()->getStmt();
					if (auto *assignment_stmt = llvm::dyn_cast<BinaryOperator>(access_stmt)) {
						if (debug_dump_enum_tag_writes) {
							assignment_stmt->dump();
						}
						SVal new_enum_value = C.getSVal(assignment_stmt->getRHS());
						for (auto &UnionAccess : pendingUnionAccesses) {
							const DynTypedNodeList parents = C.getAnalysisManager().getASTContext().getParents(*access_stmt);
							if (parents.size() == 1) {
								const CompoundStmt *compound_stmt = parents[0].get<CompoundStmt>();
								bool result = firstIsRightBeforeSecondInCompoundStmt(UnionAccess.access_stmt, access_stmt, compound_stmt, C);
								if (result) {
									result &= (UnionAccess.which_tagged_union == tagged_union_candidate);
								}
								if (result) {
									result &= !UnionAccess.IsLoad;
								}
								if (result) {
									// TODO: Check that the two exploded nodes are on the same path.
									// Maybe comparing the memregions is enough?
								}
								if (result) {
									// A matching union assignment was found for this enum assignment.
									// A matching union assignment was found for this enum assignment.
									if (debug_dump_possible_reverse_initialization) {
										llvm::errs() << "Possible reverse initialization at line "
											<< C.getSourceManager().getSpellingLineNumber(assignment_stmt->getBeginLoc())
											<< ", column "
											<< C.getSourceManager().getSpellingColumnNumber(assignment_stmt->getBeginLoc())
											<< "\n";
										assignment_stmt->dump();
										llvm::errs() << "\n";
									}
									// assert(UnionAccess.report && "Every UnionAccess should have a bugreport (which may be invalidated later, but it must exist)!");
									if (UnionAccess.report) {
										// UnionAccess.report->markInvalid(nullptr, nullptr);
										llvm::errs() << "Possibly invalidate a previous union access report!\n";
										
									}
								}
							}
						}
					}
				}
			// FIXME: This is should be super region of field_region
			// In the union case this field_region inside the union, not the union itself in the tagged union
			} else if (super_fieldregion && super_fieldregion->getDecl() == T.union_field_decl) {
				 
				// TODO: Is there a way to get the enum_field_region without calling getFieldRegion?
				MemRegionManager &m = C.getStoreManager().getRegionManager();
				const FieldRegion *enum_field_region = m.getFieldRegion(T.enum_field_decl, tagged_union_candidate.region);
				const FieldRegion *union_field_region = m.getFieldRegion(T.union_field_decl, tagged_union_candidate.region);
				QualType enum_type = enum_field_region->getValueType();

				UnionAccess a;
				a.which_tagged_union = tagged_union_candidate;
				a.IsLoad = IsLoad;
				a.tag_value = C.getState()->getSVal(enum_field_region, enum_type);
				a.accessed_union_field = field_region->getDecl();
				a.accessed_union_field_region = field_region;
				a.exploded_node = C.getPredecessor();
				a.access_stmt = C.getCFGElementRef()->getAs<clang::CFGStmt>()->getStmt(); // Should be a CFGStmt as checkLocation is load or store, right?
				a.report = nullptr;

				

				// if () {
				// 	a.report = std::make_unique<PathSensitiveBugReport>(BT, *new_message, N);
				// }

				pendingUnionAccesses.push_back(a);

				if (debug_peek_ahead_for_immediate_enum_tag_access) {
					// Peek one statement ahead in the AST to see if it is an enum tag assignment
					if (debug_dump_union_field_accesses) {
						field_region->getDecl()->dump();
					}
					if (std::optional<clang::CFGStmt> cfgstmt = C.getCFGElementRef()->getAs<clang::CFGStmt>()) {
						const DynTypedNodeList parents = C.getAnalysisManager().getASTContext().getParents(*cfgstmt->getStmt());
						if (parents.size() == 1) {
							if (const CompoundStmt *compoundstmt = parents[0].get<CompoundStmt>()) {
								const Stmt *prev = nullptr;
								for (const Stmt *s : compoundstmt->body()) {
									if (prev == cfgstmt->getStmt()) {
										if (auto *assignment_stmt = llvm::dyn_cast<BinaryOperator>(s)) {
											Expr *lhs = assignment_stmt->getLHS();
											if (MemberExpr *member_expr = llvm::dyn_cast<MemberExpr>(lhs)) {
												if (DeclRefExpr *declref_expr = llvm::dyn_cast<DeclRefExpr>(member_expr->getBase())) {

													declref_expr->dump();
													if (const RecordType *r = declref_expr->getDecl()->getType().getTypePtr()->getAsStructureType()) {
														if (r->getDecl() == tagged_union_candidate.decl) {
															// Is this the same object whose union is currently accessed in the symbolic execution? This has the same type, but it may not be the same object.
															llvm::errs() << "Potential reverse initialization!\n";
														}
													}
												}
											}
										}
									}
									prev = s;
								}
							}
						}
					}
				}
			}
			return;
		}
	}

#if 0
		const FieldRegion *union_field_region = memregion_manager.getFieldRegion(MatchCallback.union_field, tagged_union_candidate.region);
		const FieldRegion *enum_field_region = ;
		if (union_field_region && enum_field_region) {
			const ProgramStateRef &programstate = C.getState();
			QualType enum_type = enum_field_region->getValueType();
			SVal enum_value_sval = programstate->getSVal(enum_field_region, enum_type);

			for (auto *decl : T.union_decl->fields()) {
				const FieldRegion *decl_region = memregion_manager.getFieldRegion(decl, union_field_region);
				if (region->isSubRegionOf(decl_region)) {
					return;
				}
			}
		}
#endif
}

void TaggedUnionChecker::checkASTDecl(const TranslationUnitDecl *D, AnalysisManager &Mgr, BugReporter &BR) const {
    MatchCallback.initialize(&BR, Mgr.getAnalysisDeclContext(D));
	Finder.matchAST(Mgr.getASTContext());
}

void ento::registerTaggedUnionChecker(CheckerManager &Mgr) {
	Mgr.registerChecker<TaggedUnionChecker>();
}

bool ento::shouldRegisterTaggedUnionChecker(const CheckerManager &mgr) {
	return true;
}

