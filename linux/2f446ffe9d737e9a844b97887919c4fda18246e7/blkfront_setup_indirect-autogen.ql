/**
 * @name linux-2f446ffe9d737e9a844b97887919c4fda18246e7-blkfront_setup_indirect
 * @id cpp/linux/2f446ffe9d737e9a844b97887919c4fda18246e7/blkfront_setup_indirect
 * @description linux-2f446ffe9d737e9a844b97887919c4fda18246e7-blkfront_setup_indirect CVE-2022-26365
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(BitwiseOrExpr target_0 |
		target_0.getValue()="3520"
		and target_0.getLeftOperand() instanceof BitwiseOrExpr
		and target_0.getRightOperand().(Literal).getValue()="256"
		and target_0.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getTarget().hasName("alloc_pages")
		and target_0.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(BitwiseOrExpr target_1 |
		target_1.getValue()="3264"
		and target_1.getLeftOperand().(BitwiseOrExpr).getValue()="3136"
		and target_1.getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getValue()="3072"
		and target_1.getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(Literal).getValue()="1024"
		and target_1.getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="2048"
		and target_1.getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="64"
		and target_1.getRightOperand().(Literal).getValue()="128"
		and target_1.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getTarget().hasName("alloc_pages")
		and target_1.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_1.getEnclosingFunction() = func)
}

from Function func
where
not func_0(func)
and func_1(func)
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
