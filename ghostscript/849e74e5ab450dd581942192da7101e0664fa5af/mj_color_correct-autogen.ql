/**
 * @name ghostscript-849e74e5ab450dd581942192da7101e0664fa5af-mj_color_correct
 * @id cpp/ghostscript/849e74e5ab450dd581942192da7101e0664fa5af/mj-color-correct
 * @description ghostscript-849e74e5ab450dd581942192da7101e0664fa5af-contrib/japanese/gdevmjc.c-mj_color_correct CVE-2020-16298
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="1024"
		and not target_0.getValue()="768"
		and target_0.getParent().(LTExpr).getParent().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget().getType().hasName("short")
		and target_0.getEnclosingFunction() = func
}

from Function func, Literal target_0
where
func_0(func, target_0)
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
