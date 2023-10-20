/**
 * @name libtiff-1b5e3b6a23827c33acf19ad50ce5ce78f12b3773-gtStripSeparate
 * @id cpp/libtiff/1b5e3b6a23827c33acf19ad50ce5ce78f12b3773/gtStripSeparate
 * @description libtiff-1b5e3b6a23827c33acf19ad50ce5ce78f12b3773-libtiff/tif_getimage.c-gtStripSeparate CVE-2019-14973
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vtif_1005, Variable vstripsize_1014, ExprStmt target_6, ExprStmt target_7) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("_TIFFMultiplySSize")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vtif_1005
		and target_0.getArgument(1) instanceof ConditionalExpr
		and target_0.getArgument(2).(VariableAccess).getTarget()=vstripsize_1014
		and target_0.getArgument(3) instanceof StringLiteral
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_0.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("tmsize_t")
		and target_6.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getArgument(0).(VariableAccess).getLocation())
		and target_0.getArgument(0).(VariableAccess).getLocation().isBefore(target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable valpha_1017, ConditionalExpr target_1) {
		target_1.getCondition().(VariableAccess).getTarget()=valpha_1017
		and target_1.getThen().(Literal).getValue()="4"
		and target_1.getElse().(Literal).getValue()="3"
}

predicate func_2(Variable vstripsize_1014, VariableAccess target_2) {
		target_2.getTarget()=vstripsize_1014
}

predicate func_3(Variable vtif_1005, VariableAccess target_3) {
		target_3.getTarget()=vtif_1005
		and target_3.getParent().(FunctionCall).getParent().(FunctionCall).getArgument(1) instanceof FunctionCall
}

predicate func_5(Variable vstripsize_1014, Variable valpha_1017, ConditionalExpr target_5) {
		target_5.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vstripsize_1014
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(DivExpr).getLeftOperand().(MulExpr).getLeftOperand() instanceof ConditionalExpr
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(DivExpr).getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vstripsize_1014
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(DivExpr).getRightOperand().(VariableAccess).getTarget()=vstripsize_1014
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ConditionalExpr).getCondition().(VariableAccess).getTarget()=valpha_1017
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ConditionalExpr).getThen().(Literal).getValue()="4"
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ConditionalExpr).getElse().(Literal).getValue()="3"
		and target_5.getThen().(MulExpr).getLeftOperand().(ConditionalExpr).getCondition().(VariableAccess).getTarget()=valpha_1017
		and target_5.getThen().(MulExpr).getLeftOperand().(ConditionalExpr).getThen().(Literal).getValue()="4"
		and target_5.getThen().(MulExpr).getLeftOperand().(ConditionalExpr).getElse().(Literal).getValue()="3"
		and target_5.getThen().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vstripsize_1014
		and target_5.getElse().(Literal).getValue()="0"
		and target_5.getParent().(AssignExpr).getRValue() = target_5
		and target_5.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("tmsize_t")
}

predicate func_6(Variable vtif_1005, EqualityOperation target_9, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("TIFFErrorExt")
		and target_6.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tif_clientdata"
		and target_6.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtif_1005
		and target_6.getExpr().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("TIFFFileName")
		and target_6.getExpr().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_1005
		and target_6.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Integer overflow in %s"
		and target_6.getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
}

predicate func_7(Variable vtif_1005, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("TIFFGetFieldDefaulted")
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_1005
		and target_7.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="278"
		and target_7.getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("uint32")
}

predicate func_9(EqualityOperation target_9) {
		target_9.getAnOperand().(VariableAccess).getTarget().getType().hasName("tmsize_t")
		and target_9.getAnOperand().(Literal).getValue()="0"
}

from Function func, Variable vtif_1005, Variable vstripsize_1014, Variable valpha_1017, ConditionalExpr target_1, VariableAccess target_2, VariableAccess target_3, ConditionalExpr target_5, ExprStmt target_6, ExprStmt target_7, EqualityOperation target_9
where
not func_0(vtif_1005, vstripsize_1014, target_6, target_7)
and func_1(valpha_1017, target_1)
and func_2(vstripsize_1014, target_2)
and func_3(vtif_1005, target_3)
and func_5(vstripsize_1014, valpha_1017, target_5)
and func_6(vtif_1005, target_9, target_6)
and func_7(vtif_1005, target_7)
and func_9(target_9)
and vtif_1005.getType().hasName("TIFF *")
and vstripsize_1014.getType().hasName("tmsize_t")
and valpha_1017.getType().hasName("int")
and vtif_1005.(LocalVariable).getFunction() = func
and vstripsize_1014.(LocalVariable).getFunction() = func
and valpha_1017.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
