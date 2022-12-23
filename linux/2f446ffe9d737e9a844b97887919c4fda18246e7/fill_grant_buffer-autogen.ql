/**
 * @name linux-2f446ffe9d737e9a844b97887919c4fda18246e7-fill_grant_buffer
 * @id cpp/linux/2f446ffe9d737e9a844b97887919c4fda18246e7/fill_grant_buffer
 * @description linux-2f446ffe9d737e9a844b97887919c4fda18246e7-fill_grant_buffer CVE-2022-26365
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(BitwiseOrExpr target_0 |
		target_0.getValue()="3328"
		and target_0.getLeftOperand() instanceof BitwiseOrExpr
		and target_0.getRightOperand().(Literal).getValue()="256"
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("alloc_pages")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(BitwiseOrExpr target_1 |
		target_1.getValue()="3072"
		and target_1.getLeftOperand().(Literal).getValue()="1024"
		and target_1.getRightOperand().(Literal).getValue()="2048"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("alloc_pages")
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_1.getEnclosingFunction() = func)
}

from Function func
where
not func_0(func)
and func_1(func)
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
