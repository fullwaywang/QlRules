/**
 * @name systemd-9102c625a673a3246d7e73d8737f3494446bad4e-format_timespan
 * @id cpp/systemd/9102c625a673a3246d7e73d8737f3494446bad4e/format-timespan
 * @description systemd-9102c625a673a3246d7e73d8737f3494446bad4e-src/basic/time-util.c-format_timespan CVE-2022-3821
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Parameter vl_500, ExprStmt target_4, ExprStmt target_5) {
	exists(SubExpr target_1 |
		target_1.getLeftOperand().(VariableAccess).getTarget()=vl_500
		and target_1.getRightOperand().(Literal).getValue()="1"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_1.getLeftOperand().(VariableAccess).getLocation())
		and target_1.getLeftOperand().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vl_500, VariableAccess target_2) {
		target_2.getTarget()=vl_500
}

predicate func_4(Parameter vl_500, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("snprintf")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vl_500
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(StringLiteral).getValue()="%s%lu%s"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(ConditionalExpr).getThen().(StringLiteral).getValue()=" "
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(ConditionalExpr).getElse().(StringLiteral).getValue()=""
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(ValueFieldAccess).getTarget().getName()="suffix"
}

predicate func_5(Parameter vl_500, ExprStmt target_5) {
		target_5.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vl_500
}

from Function func, Parameter vl_500, VariableAccess target_2, ExprStmt target_4, ExprStmt target_5
where
not func_1(vl_500, target_4, target_5)
and func_2(vl_500, target_2)
and func_4(vl_500, target_4)
and func_5(vl_500, target_5)
and vl_500.getType().hasName("size_t")
and vl_500.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
