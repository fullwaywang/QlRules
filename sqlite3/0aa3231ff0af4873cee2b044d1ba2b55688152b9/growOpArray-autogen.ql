/**
 * @name sqlite3-0aa3231ff0af4873cee2b044d1ba2b55688152b9-growOpArray
 * @id cpp/sqlite3/0aa3231ff0af4873cee2b044d1ba2b55688152b9/growOpArray
 * @description sqlite3-0aa3231ff0af4873cee2b044d1ba2b55688152b9-src/vdbeaux.c-growOpArray CVE-2019-5827
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Parameter vv_146, ExprStmt target_8) {
	exists(ConditionalExpr target_1 |
		target_1.getCondition().(PointerFieldAccess).getTarget().getName()="nOpAlloc"
		and target_1.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vv_146
		and target_1.getThen().(MulExpr).getLeftOperand() instanceof Literal
		and target_1.getThen().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="nOpAlloc"
		and target_1.getThen().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vv_146
		and target_1.getElse() instanceof DivExpr
		and target_1.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vv_146, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="nOpAlloc"
		and target_2.getQualifier().(VariableAccess).getTarget()=vv_146
}

predicate func_3(Parameter vv_146, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="nOpAlloc"
		and target_3.getQualifier().(VariableAccess).getTarget()=vv_146
}

predicate func_4(Function func, DivExpr target_4) {
		target_4.getValue()="42"
		and target_4.getEnclosingFunction() = func
}

predicate func_7(Parameter vv_146, ConditionalExpr target_7) {
		target_7.getCondition().(PointerFieldAccess).getTarget().getName()="nOpAlloc"
		and target_7.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vv_146
		and target_7.getThen().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="nOpAlloc"
		and target_7.getThen().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vv_146
		and target_7.getThen().(MulExpr).getRightOperand() instanceof Literal
		and target_7.getElse() instanceof DivExpr
}

predicate func_8(Parameter vv_146, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("VdbeOp *")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("sqlite3DbRealloc")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="db"
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("Parse *")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="aOp"
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vv_146
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(MulExpr).getLeftOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(MulExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(MulExpr).getRightOperand().(SizeofTypeOperator).getValue()="24"
}

from Function func, Parameter vv_146, PointerFieldAccess target_2, PointerFieldAccess target_3, DivExpr target_4, ConditionalExpr target_7, ExprStmt target_8
where
not func_1(vv_146, target_8)
and func_2(vv_146, target_2)
and func_3(vv_146, target_3)
and func_4(func, target_4)
and func_7(vv_146, target_7)
and func_8(vv_146, target_8)
and vv_146.getType().hasName("Vdbe *")
and vv_146.getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
