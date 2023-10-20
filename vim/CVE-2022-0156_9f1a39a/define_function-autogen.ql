/**
 * @name vim-9f1a39a5d1cd7989ada2d1cb32f97d84360e050f-define_function
 * @id cpp/vim/9f1a39a5d1cd7989ada2d1cb32f97d84360e050f/define-function
 * @description vim-9f1a39a5d1cd7989ada2d1cb32f97d84360e050f-src/userfunc.c-define_function CVE-2022-0156
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_2(Parameter vline_to_free_3963, LogicalOrExpr target_4, VariableAccess target_2) {
		target_2.getTarget()=vline_to_free_3963
		and target_2.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getTarget().hasName("get_function_args")
		and target_2.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(1).(CharLiteral).getValue()="41"
		and target_2.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(3).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="cmdidx"
		and target_2.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(3).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_2.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_2.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_2.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getArgument(8).(PointerFieldAccess).getTarget().getName()="skip"
		and target_2.getLocation().isBefore(target_4.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(3).(VariableAccess).getLocation())
}

predicate func_3(Parameter vline_to_free_3963, EqualityOperation target_5, VariableAccess target_3) {
		target_3.getTarget()=vline_to_free_3963
		and target_3.getParent().(FunctionCall).getParent().(EQExpr).getAnOperand().(FunctionCall).getTarget().hasName("get_function_body")
		and target_5.getAnOperand().(FunctionCall).getArgument(10).(VariableAccess).getLocation().isBefore(target_3.getLocation())
}

predicate func_4(Parameter vline_to_free_3963, LogicalOrExpr target_4) {
		target_4.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("get_function_body")
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vline_to_free_3963
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_4.getAnOperand().(PointerFieldAccess).getTarget().getName()="skip"
}

predicate func_5(Parameter vline_to_free_3963, EqualityOperation target_5) {
		target_5.getAnOperand().(FunctionCall).getTarget().hasName("get_function_args")
		and target_5.getAnOperand().(FunctionCall).getArgument(1).(CharLiteral).getValue()="41"
		and target_5.getAnOperand().(FunctionCall).getArgument(3).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="cmdidx"
		and target_5.getAnOperand().(FunctionCall).getArgument(3).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_5.getAnOperand().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_5.getAnOperand().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_5.getAnOperand().(FunctionCall).getArgument(8).(PointerFieldAccess).getTarget().getName()="skip"
		and target_5.getAnOperand().(FunctionCall).getArgument(10).(VariableAccess).getTarget()=vline_to_free_3963
		and target_5.getAnOperand().(Literal).getValue()="0"
}

from Function func, Parameter vline_to_free_3963, VariableAccess target_2, VariableAccess target_3, LogicalOrExpr target_4, EqualityOperation target_5
where
func_2(vline_to_free_3963, target_4, target_2)
and func_3(vline_to_free_3963, target_5, target_3)
and func_4(vline_to_free_3963, target_4)
and func_5(vline_to_free_3963, target_5)
and vline_to_free_3963.getType().hasName("char_u **")
and vline_to_free_3963.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
