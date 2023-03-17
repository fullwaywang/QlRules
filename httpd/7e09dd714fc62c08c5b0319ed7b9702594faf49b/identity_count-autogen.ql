/**
 * @name httpd-7e09dd714fc62c08c5b0319ed7b9702594faf49b-identity_count
 * @id cpp/httpd/7e09dd714fc62c08c5b0319ed7b9702594faf49b/identity-count
 * @description httpd-7e09dd714fc62c08c5b0319ed7b9702594faf49b-identity_count CVE-2021-26691
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="1"
		and not target_0.getValue()="2"
		and target_0.getParent().(AddExpr).getParent().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(FunctionCall).getTarget().hasName("strlen")
		and target_0.getParent().(AddExpr).getParent().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(Literal).getValue()="3"
		and target_0.getParent().(AddExpr).getParent().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(FunctionCall).getTarget().hasName("strlen")
		and target_0.getParent().(AddExpr).getParent().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(Literal).getValue()="3"
		and target_0.getEnclosingFunction() = func
}

from Function func, Literal target_0
where
func_0(func, target_0)
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
