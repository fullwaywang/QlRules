/**
 * @name git-a937b37e76-init_revisions
 * @id cpp/git/a937b37e76/init-revisions
 * @description git-a937b37e76-revision.c-init_revisions CVE-2017-15298
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, SizeofExprOperator target_0) {
		target_0.getValue()="2120"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Parameter vrevs_1338, ExprStmt target_2, ExprStmt target_3, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="change_fn_data"
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pruning"
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrevs_1338
		and target_1.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vrevs_1338
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_1)
		and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vrevs_1338, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="change"
		and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pruning"
		and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrevs_1338
}

predicate func_3(Parameter vrevs_1338, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="sort_order"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrevs_1338
}

from Function func, Parameter vrevs_1338, SizeofExprOperator target_0, ExprStmt target_2, ExprStmt target_3
where
func_0(func, target_0)
and not func_1(vrevs_1338, target_2, target_3, func)
and func_2(vrevs_1338, target_2)
and func_3(vrevs_1338, target_3)
and vrevs_1338.getType().hasName("rev_info *")
and vrevs_1338.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
