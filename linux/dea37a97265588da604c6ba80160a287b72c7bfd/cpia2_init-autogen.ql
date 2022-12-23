/**
 * @name linux-dea37a97265588da604c6ba80160a287b72c7bfd-cpia2_init
 * @id cpp/linux/dea37a97265588da604c6ba80160a287b72c7bfd/cpia2-init
 * @description linux-dea37a97265588da604c6ba80160a287b72c7bfd-cpia2_init 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("cpia2_usb_init")
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr() instanceof FunctionCall
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1)
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="0"
		and target_2.getEnclosingFunction() = func)
}

from Function func
where
func_0(func)
and func_1(func)
and func_2(func)
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
