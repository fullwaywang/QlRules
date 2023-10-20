/**
 * @name openssh-391ffc4b9d31fa1f4ad566499fef9176ff8a07dc-main
 * @id cpp/openssh/391ffc4b9d31fa1f4ad566499fef9176ff8a07dc/main
 * @description openssh-391ffc4b9d31fa1f4ad566499fef9176ff8a07dc-scp.c-main CVE-2019-6111
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vfflag_394, Variable vtflag_394, VariableAccess target_0) {
		target_0.getTarget()=vfflag_394
		and target_0.getParent().(AssignExpr).getLValue() = target_0
		and target_0.getParent().(AssignExpr).getRValue().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtflag_394
		and target_0.getParent().(AssignExpr).getRValue().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_1(Function func, StringLiteral target_1) {
		target_1.getValue()="dfl:prtvBCc:i:P:q12346S:o:F:J:"
		and not target_1.getValue()="dfl:prtTvBCc:i:P:q12346S:o:F:J:"
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Variable vfflag_394, Variable vtflag_394) {
	exists(AssignExpr target_2 |
		target_2.getLValue().(VariableAccess).getTarget()=vfflag_394
		and target_2.getRValue().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_2.getRValue().(AssignExpr).getRValue().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtflag_394
		and target_2.getRValue().(AssignExpr).getRValue().(AssignExpr).getRValue().(Literal).getValue()="0")
}

predicate func_3(Function func) {
	exists(SwitchCase target_3 |
		target_3.getExpr().(CharLiteral).getValue()="84"
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(VariableAccess target_8, Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_4.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_4.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_8
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(VariableAccess target_8, Function func) {
	exists(BreakStmt target_5 |
		target_5.toString() = "break;"
		and target_5.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_8
		and target_5.getEnclosingFunction() = func)
}

predicate func_7(Function func, LabelStmt target_7) {
		target_7.toString() = "label ...:"
		and target_7.getEnclosingFunction() = func
}

predicate func_8(Variable vch_394, VariableAccess target_8) {
		target_8.getTarget()=vch_394
}

from Function func, Variable vch_394, Variable vfflag_394, Variable vtflag_394, VariableAccess target_0, StringLiteral target_1, LabelStmt target_7, VariableAccess target_8
where
func_0(vfflag_394, vtflag_394, target_0)
and func_1(func, target_1)
and not func_2(vfflag_394, vtflag_394)
and not func_3(func)
and not func_4(target_8, func)
and not func_5(target_8, func)
and func_7(func, target_7)
and func_8(vch_394, target_8)
and vch_394.getType().hasName("int")
and vfflag_394.getType().hasName("int")
and vtflag_394.getType().hasName("int")
and vch_394.getParentScope+() = func
and vfflag_394.getParentScope+() = func
and vtflag_394.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
