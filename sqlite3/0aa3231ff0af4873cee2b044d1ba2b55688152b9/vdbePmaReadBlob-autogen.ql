/**
 * @name sqlite3-0aa3231ff0af4873cee2b044d1ba2b55688152b9-vdbePmaReadBlob
 * @id cpp/sqlite3/0aa3231ff0af4873cee2b044d1ba2b55688152b9/vdbePmaReadBlob
 * @description sqlite3-0aa3231ff0af4873cee2b044d1ba2b55688152b9-src/vdbesort.c-vdbePmaReadBlob CVE-2019-5827
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Parameter vp_487, RelationalOperation target_10, ExprStmt target_11) {
	exists(ConditionalExpr target_1 |
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="128"
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(MulExpr).getLeftOperand() instanceof Literal
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="nAlloc"
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_487
		and target_1.getThen().(Literal).getValue()="128"
		and target_1.getElse().(MulExpr).getLeftOperand() instanceof Literal
		and target_1.getElse().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="nAlloc"
		and target_1.getElse().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_487
		and target_10.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getCondition().(RelationalOperation).getLesserOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_2(Parameter vp_487, RelationalOperation target_10) {
	exists(MulExpr target_2 |
		target_2.getLeftOperand() instanceof Literal
		and target_2.getRightOperand().(PointerFieldAccess).getTarget().getName()="nAlloc"
		and target_2.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_487
		and target_2.getParent().(GTExpr).getGreaterOperand().(Literal).getValue()="128"
		and target_2.getParent().(GTExpr).getLesserOperand() instanceof MulExpr
		and target_10.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
predicate func_3(Parameter vp_487, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="nAlloc"
		and target_3.getQualifier().(VariableAccess).getTarget()=vp_487
}

predicate func_4(Parameter vp_487, PointerFieldAccess target_4) {
		target_4.getTarget().getName()="nAlloc"
		and target_4.getQualifier().(VariableAccess).getTarget()=vp_487
}

predicate func_8(Parameter vp_487, ConditionalExpr target_8) {
		target_8.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="128"
		and target_8.getCondition().(RelationalOperation).getLesserOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="nAlloc"
		and target_8.getCondition().(RelationalOperation).getLesserOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_487
		and target_8.getCondition().(RelationalOperation).getLesserOperand().(MulExpr).getRightOperand() instanceof Literal
		and target_8.getThen().(Literal).getValue()="128"
		and target_8.getElse().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="nAlloc"
		and target_8.getElse().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_487
		and target_8.getElse().(MulExpr).getRightOperand() instanceof Literal
}

/*predicate func_9(Parameter vp_487, RelationalOperation target_10, MulExpr target_9) {
		target_9.getLeftOperand().(PointerFieldAccess).getTarget().getName()="nAlloc"
		and target_9.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_487
		and target_9.getRightOperand() instanceof Literal
		and target_9.getParent().(GTExpr).getGreaterOperand().(Literal).getValue()="128"
		and target_10.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

*/
predicate func_10(Parameter vp_487, RelationalOperation target_10) {
		 (target_10 instanceof GTExpr or target_10 instanceof LTExpr)
		and target_10.getLesserOperand().(PointerFieldAccess).getTarget().getName()="nAlloc"
		and target_10.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_487
		and target_10.getGreaterOperand().(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_11(Parameter vp_487, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("u8 *")
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("sqlite3Realloc")
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="aAlloc"
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_487
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("int")
}

from Function func, Parameter vp_487, PointerFieldAccess target_3, PointerFieldAccess target_4, ConditionalExpr target_8, RelationalOperation target_10, ExprStmt target_11
where
not func_1(vp_487, target_10, target_11)
and func_3(vp_487, target_3)
and func_4(vp_487, target_4)
and func_8(vp_487, target_8)
and func_10(vp_487, target_10)
and func_11(vp_487, target_11)
and vp_487.getType().hasName("PmaReader *")
and vp_487.getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
