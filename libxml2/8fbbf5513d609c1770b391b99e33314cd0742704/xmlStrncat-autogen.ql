/**
 * @name libxml2-8fbbf5513d609c1770b391b99e33314cd0742704-xmlStrncat
 * @id cpp/libxml2/8fbbf5513d609c1770b391b99e33314cd0742704/xmlStrncat
 * @description libxml2-8fbbf5513d609c1770b391b99e33314cd0742704-xmlStrncat CVE-2016-1834
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vsize_449, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vsize_449
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vcur_448, Variable vsize_449) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(VariableAccess).getTarget()=vsize_449
		and target_1.getRValue().(FunctionCall).getTarget().hasName("xmlStrlen")
		and target_1.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcur_448)
}

from Function func, Parameter vcur_448, Variable vsize_449
where
not func_0(vsize_449, func)
and vsize_449.getType().hasName("int")
and func_1(vcur_448, vsize_449)
and vcur_448.getParentScope+() = func
and vsize_449.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
