/**
 * @name libxml2-652dd12a858989b14eed4e84e453059cd3ba340e-xmlRemoveID
 * @id cpp/libxml2/652dd12a858989b14eed4e84e453059cd3ba340e/xmlRemoveID
 * @description libxml2-652dd12a858989b14eed4e84e453059cd3ba340e-valid.c-xmlRemoveID CVE-2022-23308
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vID_2811, EqualityOperation target_1, ExprStmt target_2, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("xmlValidNormalizeString")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vID_2811
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_0)
		and target_1.getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_1(Variable vID_2811, EqualityOperation target_1) {
		target_1.getAnOperand().(VariableAccess).getTarget()=vID_2811
		and target_1.getAnOperand().(Literal).getValue()="0"
}

predicate func_2(Variable vID_2811, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("xmlIDPtr")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlHashLookup")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("xmlIDTablePtr")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vID_2811
}

from Function func, Variable vID_2811, EqualityOperation target_1, ExprStmt target_2
where
not func_0(vID_2811, target_1, target_2, func)
and func_1(vID_2811, target_1)
and func_2(vID_2811, target_2)
and vID_2811.getType().hasName("xmlChar *")
and vID_2811.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
