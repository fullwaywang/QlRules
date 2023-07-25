/**
 * @name httpd-40bf351edc852c86e9a6bb85ef6d7f5b6a2bee3a-set_pattern
 * @id cpp/httpd/40bf351edc852c86e9a6bb85ef6d7f5b6a2bee3a/set-pattern
 * @description httpd-40bf351edc852c86e9a6bb85ef6d7f5b6a2bee3a-modules/filters/mod_substitute.c-set_pattern CVE-2020-1927
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="0"
		and not target_0.getValue()="1024"
		and target_0.getParent().(BitwiseOrExpr).getParent().(FunctionCall).getArgument(2).(BitwiseOrExpr).getRightOperand().(ConditionalExpr).getCondition().(VariableAccess).getTarget().getType().hasName("int")
		and target_0.getParent().(BitwiseOrExpr).getParent().(FunctionCall).getArgument(2).(BitwiseOrExpr).getRightOperand().(ConditionalExpr).getThen().(Literal).getValue()="1"
		and target_0.getParent().(BitwiseOrExpr).getParent().(FunctionCall).getArgument(2).(BitwiseOrExpr).getRightOperand().(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func) {
	exists(BitwiseOrExpr target_1 |
		target_1.getLeftOperand().(Literal).getValue()="1024"
		and target_1.getRightOperand().(BitwiseAndExpr).getLeftOperand().(FunctionCall).getTarget().hasName("ap_regcomp_get_default_cflags")
		and target_1.getRightOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="512"
		and target_1.getParent().(BitwiseOrExpr).getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ap_pregcomp")
		and target_1.getParent().(BitwiseOrExpr).getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="pool"
		and target_1.getParent().(BitwiseOrExpr).getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("cmd_parms *")
		and target_1.getParent().(BitwiseOrExpr).getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("char *")
		and target_1.getParent().(BitwiseOrExpr).getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(BitwiseOrExpr).getLeftOperand() instanceof Literal
		and target_1.getParent().(BitwiseOrExpr).getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(BitwiseOrExpr).getRightOperand().(ConditionalExpr).getCondition().(VariableAccess).getTarget().getType().hasName("int")
		and target_1.getParent().(BitwiseOrExpr).getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(BitwiseOrExpr).getRightOperand().(ConditionalExpr).getThen().(Literal).getValue()="1"
		and target_1.getParent().(BitwiseOrExpr).getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(BitwiseOrExpr).getRightOperand().(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_1.getEnclosingFunction() = func)
}

from Function func, Literal target_0
where
func_0(func, target_0)
and not func_1(func)
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
