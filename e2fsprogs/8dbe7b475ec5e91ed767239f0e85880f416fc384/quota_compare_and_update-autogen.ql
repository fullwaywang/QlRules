/**
 * @name e2fsprogs-8dbe7b475ec5e91ed767239f0e85880f416fc384-quota_compare_and_update
 * @id cpp/e2fsprogs/8dbe7b475ec5e91ed767239f0e85880f416fc384/quota-compare-and-update
 * @description e2fsprogs-8dbe7b475ec5e91ed767239f0e85880f416fc384-lib/support/mkquota.c-quota_compare_and_update CVE-2019-5094
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vusage_inconsistent_648, VariableAccess target_1, ExprStmt target_2) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vusage_inconsistent_648
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_0.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable verr_655, VariableAccess target_1) {
		target_1.getTarget()=verr_655
}

predicate func_2(Parameter vusage_inconsistent_648, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vusage_inconsistent_648
		and target_2.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="usage_is_inconsistent"
}

from Function func, Parameter vusage_inconsistent_648, Variable verr_655, VariableAccess target_1, ExprStmt target_2
where
not func_0(vusage_inconsistent_648, target_1, target_2)
and func_1(verr_655, target_1)
and func_2(vusage_inconsistent_648, target_2)
and vusage_inconsistent_648.getType().hasName("int *")
and verr_655.getType().hasName("errcode_t")
and vusage_inconsistent_648.getParentScope+() = func
and verr_655.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
