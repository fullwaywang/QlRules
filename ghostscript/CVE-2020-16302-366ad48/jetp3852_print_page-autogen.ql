/**
 * @name ghostscript-366ad48d076c1aa4c8f83c65011258a04e348207-jetp3852_print_page
 * @id cpp/ghostscript/366ad48d076c1aa4c8f83c65011258a04e348207/jetp3852-print-page
 * @description ghostscript-366ad48d076c1aa4c8f83c65011258a04e348207-devices/gdev3852.c-jetp3852_print_page CVE-2020-16302
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vend_data_88, EqualityOperation target_6, Literal target_0) {
		target_0.getValue()="0"
		and not target_0.getValue()="84"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memset")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vend_data_88
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="7"
		and target_6.getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

/*predicate func_1(Variable vend_data_88, EqualityOperation target_6, Literal target_1) {
		target_1.getValue()="7"
		and not target_1.getValue()="86"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memset")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vend_data_88
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_6.getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

*/
predicate func_5(Variable vend_data_88, EqualityOperation target_6, VariableAccess target_5) {
		target_5.getTarget()=vend_data_88
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memset")
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_6.getAnOperand().(VariableAccess).getLocation().isBefore(target_5.getLocation())
}

predicate func_6(Variable vend_data_88, EqualityOperation target_6) {
		target_6.getAnOperand().(VariableAccess).getTarget()=vend_data_88
		and target_6.getAnOperand().(VariableAccess).getTarget().getType().hasName("byte[768]")
}

from Function func, Variable vend_data_88, Literal target_0, VariableAccess target_5, EqualityOperation target_6
where
func_0(vend_data_88, target_6, target_0)
and func_5(vend_data_88, target_6, target_5)
and func_6(vend_data_88, target_6)
and vend_data_88.getType().hasName("byte *")
and vend_data_88.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
