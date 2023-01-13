/**
 * @name libexpat-11f8838bf99ea0a6f0b76f9760c43704d00c4ff6-setElementTypePrefix
 * @id cpp/libexpat/11f8838bf99ea0a6f0b76f9760c43704d00c4ff6/setElementTypePrefix
 * @description libexpat-11f8838bf99ea0a6f0b76f9760c43704d00c4ff6-setElementTypePrefix CVE-2018-20843
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vname_6054) {
	exists(BreakStmt target_0 |
		target_0.toString() = "break;"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vname_6054
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="58")
}

from Function func, Variable vname_6054
where
not func_0(vname_6054)
and vname_6054.getType().hasName("const XML_Char *")
and vname_6054.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
