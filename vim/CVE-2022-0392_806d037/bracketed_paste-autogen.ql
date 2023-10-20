/**
 * @name vim-806d037671e133bd28a7864248763f643967973a-bracketed_paste
 * @id cpp/vim/806d037671e133bd28a7864248763f643967973a/bracketed-paste
 * @description vim-806d037671e133bd28a7864248763f643967973a-src/edit.c-bracketed_paste CVE-2022-0392
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vidx_4406, ExprStmt target_4, ExprStmt target_5) {
	exists(AddExpr target_0 |
		target_0.getAnOperand().(VariableAccess).getTarget()=vidx_4406
		and target_0.getAnOperand() instanceof Literal
		and target_0.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getTarget().hasName("ga_grow")
		and target_0.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vidx_4406
		and target_4.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(VariableAccess).getLocation().isBefore(target_5.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_3(Variable vidx_4406, VariableAccess target_3) {
		target_3.getTarget()=vidx_4406
		and target_3.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getTarget().hasName("ga_grow")
}

predicate func_4(Variable vidx_4406, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("put_on_cmdline")
		and target_4.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vidx_4406
		and target_4.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="1"
}

predicate func_5(Variable vidx_4406, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("memmove")
		and target_5.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="ga_data"
		and target_5.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="ga_len"
		and target_5.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vidx_4406
}

from Function func, Variable vidx_4406, VariableAccess target_3, ExprStmt target_4, ExprStmt target_5
where
not func_0(vidx_4406, target_4, target_5)
and func_3(vidx_4406, target_3)
and func_4(vidx_4406, target_4)
and func_5(vidx_4406, target_5)
and vidx_4406.getType().hasName("int")
and vidx_4406.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
