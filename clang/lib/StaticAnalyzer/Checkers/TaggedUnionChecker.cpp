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

	void processUnionAccess(SVal tag_value, UnionAccess &a, TaggedUnion &T, const FieldRegion *enum_field_region, SVal Loc, CheckerContext &C) const;
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

static std::vector<std::string> report_messages;

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

static const bool debug_dump_candidate_tagged_union = false;
static const bool debug_dump_union_field_accesses = false;
static const bool debug_peek_ahead_for_immediate_enum_tag_access = false;
static const bool debug_dump_enum_tag_writes = false;
static const bool debug_dump_possible_reverse_initialization = true;

void TaggedUnionChecker::processUnionAccess(SVal tag_value, UnionAccess &a, TaggedUnion &T, const FieldRegion *enum_field_region, SVal Loc, CheckerContext &C) const {
	if (tag_value.getAsInteger() && a.accessed_union_field) {
		auto &map_for_current = tagged_union_invariants[a.which_tagged_union.decl];
		auto expected_field = map_for_current.find(*tag_value.getAsInteger());
		if (expected_field != map_for_current.end()) {
			if (a.accessed_union_field != expected_field->second) {
				ExplodedNode *N = C.generateNonFatalErrorNode();

				EnumDecl *enum_declaration = llvm::dyn_cast<EnumDecl>(T.enum_field_decl->getType().getCanonicalType().getTypePtr()->getAsTagDecl());
				const EnumConstantDecl *matched_decl = nullptr;
				for (const EnumConstantDecl *Enumerator : enum_declaration->enumerators()) {
					if (Enumerator->getInitVal().isRepresentableByInt64() && tag_value.getAsInteger()->isRepresentableByInt64() && Enumerator->getInitVal().getExtValue() == tag_value.getAsInteger()->getExtValue()) {
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
				Report->markInteresting(a.accessed_union_field_region);
				Report->markInteresting(enum_field_region);
				bugreporter::trackStoredValue(Loc, a.accessed_union_field_region, *Report);

				if (a.report) {
					// If the union access caused a report, but then it turns out that it part of a reverse tagged union initialization,
					// where even that reverse initialization also causes a report at the enum update, then the reverse initialization report should
					// be presented to the user and the earlier one for the union access should be marked as invalid.
					a.report->markInvalid(nullptr, nullptr);
				} else {
					a.report = Report.get();
				}

				C.emitReport(std::move(Report));
			} else if (a.report) {
				a.report->markInvalid(nullptr, nullptr);
			}
		} else {
			map_for_current.emplace(*tag_value.getAsInteger(), a.accessed_union_field);
			ExplodedNode *N = C.generateNonFatalErrorNode();

			EnumDecl *enum_declaration = llvm::dyn_cast<EnumDecl>(T.enum_field_decl->getType().getCanonicalType().getTypePtr()->getAsTagDecl());
			const EnumConstantDecl *matched_decl;
			for (const EnumConstantDecl *Enumerator : enum_declaration->enumerators()) {
				if (Enumerator->getInitVal().isRepresentableByInt64() && tag_value.getAsInteger()->isRepresentableByInt64() && Enumerator->getInitVal().getExtValue() == tag_value.getAsInteger()->getExtValue()) {
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
			Report->markInteresting(a.accessed_union_field_region);
			Report->markInteresting(enum_field_region);
			bugreporter::trackStoredValue(Loc, a.accessed_union_field_region, *Report);
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
						llvm::errs() << new_enum_value.getKind() << '\n';
						llvm::errs() << clang::ento::SVal::SValKind::UndefinedValKind << '\n';
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
									llvm::errs() << "Possibly invalidate a previous union access report!\n";
									processUnionAccess(new_enum_value, UnionAccess, T, field_region, Loc, C);
								}
							}
						}
					}
				} else {
					C.addTransition(C.getState(), C.getNoteTag([field_region](PathSensitiveBugReport &BR) {
						return "The tag field of this tagged union is changed here";
					}));
				}
			} else if (super_fieldregion && super_fieldregion->getDecl() == T.union_field_decl) {
				 
				// TODO: Is there a way to get the enum_field_region without calling getFieldRegion?
				MemRegionManager &m = C.getStoreManager().getRegionManager();
				const FieldRegion *enum_field_region = m.getFieldRegion(T.enum_field_decl, tagged_union_candidate.region);
				// TODO: Is this necessary to retrive or not?
				// const FieldRegion *union_field_region = m.getFieldRegion(T.union_field_decl, tagged_union_candidate.region);
				QualType enum_type = enum_field_region->getValueType();

				UnionAccess a;
				a.which_tagged_union = tagged_union_candidate;
				a.IsLoad = IsLoad;
				a.accessed_union_field = field_region->getDecl();
				a.accessed_union_field_region = field_region;
				a.exploded_node = C.getPredecessor();
				a.access_stmt = C.getCFGElementRef()->getAs<clang::CFGStmt>()->getStmt(); // Should be a CFGStmt, as checkLocation is load or store, right?
				a.report = nullptr;
				processUnionAccess(C.getState()->getSVal(enum_field_region, enum_type), a, T, enum_field_region, Loc, C);
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
