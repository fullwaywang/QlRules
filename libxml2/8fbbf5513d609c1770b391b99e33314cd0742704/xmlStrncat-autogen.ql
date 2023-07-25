/**
 * @name libxml2-8fbbf5513d609c1770b391b99e33314cd0742704-xmlStrncat
 * @id cpp/libxml2/8fbbf5513d609c1770b391b99e33314cd0742704/xmlStrncat
 * @description libxml2-8fbbf5513d609c1770b391b99e33314cd0742704-xmlstring.c-xmlStrncat CVE-2016-1834
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vsize_449, ExprStmt target_1, MulExpr target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vsize_449
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_2.getLeftOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vsize_449, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsize_449
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlStrlen")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("xmlChar *")
}

predicate func_2(Variable vsize_449, MulExpr target_2) {
		target_2.getLeftOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vsize_449
		and target_2.getLeftOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_2.getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_2.getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_2.getRightOperand().(SizeofTypeOperator).getValue()="1"
}

from Function func, Variable vsize_449, ExprStmt target_1, MulExpr target_2
where
not func_0(vsize_449, target_1, target_2, func)
and func_1(vsize_449, target_1)
and func_2(vsize_449, target_2)
and vsize_449.getType().hasName("int")
and vsize_449.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
