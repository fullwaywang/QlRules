/**
 * @name libxml2-9ab01a277d71f54d3143c2cf333c5c2e9aaedd9e-xmlXPtrNewContext
 * @id cpp/libxml2/9ab01a277d71f54d3143c2cf333c5c2e9aaedd9e/xmlXPtrNewContext
 * @description libxml2-9ab01a277d71f54d3143c2cf333c5c2e9aaedd9e-xpointer.c-xmlXPtrNewContext CVE-2016-5131
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vret_1326, Function func, ExprStmt target_0) {
		target_0.getExpr().(FunctionCall).getTarget().hasName("xmlXPathRegisterFunc")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vret_1326
		and target_0.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="range-to"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0
}

from Function func, Variable vret_1326, ExprStmt target_0
where
func_0(vret_1326, func, target_0)
and vret_1326.getType().hasName("xmlXPathContextPtr")
and vret_1326.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
