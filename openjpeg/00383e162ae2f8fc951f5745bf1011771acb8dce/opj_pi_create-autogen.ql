/**
 * @name openjpeg-00383e162ae2f8fc951f5745bf1011771acb8dce-opj_pi_create
 * @id cpp/openjpeg/00383e162ae2f8fc951f5745bf1011771acb8dce/opj-pi-create
 * @description openjpeg-00383e162ae2f8fc951f5745bf1011771acb8dce-src/lib/openjp2/pi.c-opj_pi_create CVE-2020-27841
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, SizeofTypeOperator target_0) {
		target_0.getType() instanceof LongType
		and target_0.getValue()="248"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Variable vl_current_pi_1003, ExprStmt target_2, ExprStmt target_3) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="manager"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_current_pi_1003
		and target_1.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("opj_event_mgr_t *")
		and target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vl_current_pi_1003, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vl_current_pi_1003
}

predicate func_3(Variable vl_current_pi_1003, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="comps"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_current_pi_1003
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("opj_calloc")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="numcomps"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="24"
}

from Function func, Variable vl_current_pi_1003, SizeofTypeOperator target_0, ExprStmt target_2, ExprStmt target_3
where
func_0(func, target_0)
and not func_1(vl_current_pi_1003, target_2, target_3)
and func_2(vl_current_pi_1003, target_2)
and func_3(vl_current_pi_1003, target_3)
and vl_current_pi_1003.getType().hasName("opj_pi_iterator_t *")
and vl_current_pi_1003.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
