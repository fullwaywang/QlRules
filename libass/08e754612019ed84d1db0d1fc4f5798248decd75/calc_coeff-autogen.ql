/**
 * @name libass-08e754612019ed84d1db0d1fc4f5798248decd75-calc_coeff
 * @id cpp/libass/08e754612019ed84d1db0d1fc4f5798248decd75/calc-coeff
 * @description libass-08e754612019ed84d1db0d1fc4f5798248decd75-libass/ass_blur.c-calc_coeff CVE-2016-7970
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Function func, SubExpr target_1) {
		target_1.getValue()="72"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memset")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="4"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_1.getEnclosingFunction() = func
}

from Function func, SubExpr target_1
where
func_1(func, target_1)
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
