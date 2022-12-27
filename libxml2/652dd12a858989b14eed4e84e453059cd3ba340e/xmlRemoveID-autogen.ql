/**
 * @name libxml2-652dd12a858989b14eed4e84e453059cd3ba340e-xmlRemoveID
 * @id cpp/libxml2/652dd12a858989b14eed4e84e453059cd3ba340e/xmlRemoveID
 * @description libxml2-652dd12a858989b14eed4e84e453059cd3ba340e-xmlRemoveID CVE-2022-23308
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vID_2811, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("xmlValidNormalizeString")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vID_2811
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_0))
}

predicate func_1(Variable vID_2811) {
	exists(EqualityOperation target_1 |
		target_1.getAnOperand().(VariableAccess).getTarget()=vID_2811
		and target_1.getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1")
}

from Function func, Variable vID_2811
where
not func_0(vID_2811, func)
and vID_2811.getType().hasName("xmlChar *")
and func_1(vID_2811)
and vID_2811.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
