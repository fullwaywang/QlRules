/**
 * @name libtiff-cfbb883bf6ea7bedcb04177cc4e52d304522fdff-readSeparateTilesIntoBuffer
 * @id cpp/libtiff/cfbb883bf6ea7bedcb04177cc4e52d304522fdff/readSeparateTilesIntoBuffer
 * @description libtiff-cfbb883bf6ea7bedcb04177cc4e52d304522fdff-tools/tiffcrop.c-readSeparateTilesIntoBuffer CVE-2022-3598
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="8"
		and not target_0.getValue()="3"
		and target_0.getParent().(AddExpr).getParent().(FunctionCall).getArgument(0).(AddExpr).getAnOperand().(VariableAccess).getTarget().getType().hasName("tsize_t")
		and target_0.getEnclosingFunction() = func
}

from Function func, Literal target_0
where
func_0(func, target_0)
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
