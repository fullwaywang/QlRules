/**
 * @name libxml2-50f06b3efb638efb0abd95dc62dca05ae67882c2-xmlHTMLEncodeSend
 * @id cpp/libxml2/50f06b3efb638efb0abd95dc62dca05ae67882c2/xmlHTMLEncodeSend
 * @description libxml2-50f06b3efb638efb0abd95dc62dca05ae67882c2-xmlHTMLEncodeSend CVE-2020-24977
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("memset")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getType().hasName("char[50000]")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(SizeofExprOperator).getExprOperand().(VariableAccess).getType().hasName("char[50000]")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="4"
		and target_0.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_0.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="4"
		and (func.getEntryPoint().(BlockStmt).getStmt(1)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(1).getFollowingStmt()=target_0))
}

from Function func
where
not func_0(func)
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
