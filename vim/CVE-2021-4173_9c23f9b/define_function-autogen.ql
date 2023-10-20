/**
 * @name vim-9c23f9bb5fe435b28245ba8ac65aa0ca6b902c04-define_function
 * @id cpp/vim/9c23f9bb5fe435b28245ba8ac65aa0ca6b902c04/define-function
 * @description vim-9c23f9bb5fe435b28245ba8ac65aa0ca6b902c04-src/userfunc.c-define_function CVE-2021-4173
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_2(Function func, DeclStmt target_2) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

predicate func_3(Variable vline_to_free_3993, AddressOfExpr target_3) {
		target_3.getOperand().(VariableAccess).getTarget()=vline_to_free_3993
		and target_3.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getTarget().hasName("get_function_args")
		and target_3.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(1).(CharLiteral).getValue()="41"
		and target_3.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(3).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="cmdidx"
		and target_3.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(3).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_3.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_3.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_3.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(8).(PointerFieldAccess).getTarget().getName()="skip"
}

predicate func_4(Variable vline_to_free_3993, ExprStmt target_5, AddressOfExpr target_4) {
		target_4.getOperand().(VariableAccess).getTarget()=vline_to_free_3993
		and target_4.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getTarget().hasName("get_function_body")
		and target_4.getOperand().(VariableAccess).getLocation().isBefore(target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_5(Variable vline_to_free_3993, Function func, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("vim_free")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vline_to_free_3993
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_5
}

from Function func, Variable vline_to_free_3993, DeclStmt target_2, AddressOfExpr target_3, AddressOfExpr target_4, ExprStmt target_5
where
func_2(func, target_2)
and func_3(vline_to_free_3993, target_3)
and func_4(vline_to_free_3993, target_5, target_4)
and func_5(vline_to_free_3993, func, target_5)
and vline_to_free_3993.getType().hasName("char_u *")
and vline_to_free_3993.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
