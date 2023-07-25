/**
 * @name imagemagick-d8ab7f046587f2e9f734b687ba7e6e10147c294b-GetEXIFProperty
 * @id cpp/imagemagick/d8ab7f046587f2e9f734b687ba7e6e10147c294b/GetEXIFProperty
 * @description imagemagick-d8ab7f046587f2e9f734b687ba7e6e10147c294b-MagickCore/property.c-GetEXIFProperty CVE-2016-5841
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vexif_1192, Variable vlength_1208, Variable vq_1387, LogicalOrExpr target_2, ExprStmt target_3, LogicalOrExpr target_4, ExprStmt target_5, EqualityOperation target_6) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vq_1387
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vexif_1192
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vlength_1208
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="12"
		and target_0.getThen().(BreakStmt).toString() = "break;"
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_6.getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_1(Variable vcomponents_1394, ExprStmt target_7, ExprStmt target_8) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcomponents_1394
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_1.getThen().(BreakStmt).toString() = "break;"
		and target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable vexif_1192, Variable vlength_1208, LogicalOrExpr target_2) {
		target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vexif_1192
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vexif_1192
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vlength_1208
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="2"
}

predicate func_3(Variable vexif_1192, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vexif_1192
}

predicate func_4(Variable vlength_1208, LogicalOrExpr target_4) {
		target_4.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_4.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlength_1208
}

predicate func_5(Variable vq_1387, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vq_1387
		and target_5.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(Literal).getValue()="12"
		and target_5.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="2"
}

predicate func_6(Variable vq_1387, EqualityOperation target_6) {
		target_6.getAnOperand().(FunctionCall).getTarget().hasName("GetValueFromSplayTree")
		and target_6.getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vq_1387
		and target_6.getAnOperand().(VariableAccess).getTarget()=vq_1387
}

predicate func_7(Variable vq_1387, Variable vcomponents_1394, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcomponents_1394
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ReadPropertySignedLong")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vq_1387
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="4"
}

predicate func_8(Variable vcomponents_1394, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vcomponents_1394
}

from Function func, Variable vexif_1192, Variable vlength_1208, Variable vq_1387, Variable vcomponents_1394, LogicalOrExpr target_2, ExprStmt target_3, LogicalOrExpr target_4, ExprStmt target_5, EqualityOperation target_6, ExprStmt target_7, ExprStmt target_8
where
not func_0(vexif_1192, vlength_1208, vq_1387, target_2, target_3, target_4, target_5, target_6)
and not func_1(vcomponents_1394, target_7, target_8)
and func_2(vexif_1192, vlength_1208, target_2)
and func_3(vexif_1192, target_3)
and func_4(vlength_1208, target_4)
and func_5(vq_1387, target_5)
and func_6(vq_1387, target_6)
and func_7(vq_1387, vcomponents_1394, target_7)
and func_8(vcomponents_1394, target_8)
and vexif_1192.getType().hasName("const unsigned char *")
and vlength_1208.getType().hasName("size_t")
and vq_1387.getType().hasName("unsigned char *")
and vcomponents_1394.getType().hasName("ssize_t")
and vexif_1192.getParentScope+() = func
and vlength_1208.getParentScope+() = func
and vq_1387.getParentScope+() = func
and vcomponents_1394.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
