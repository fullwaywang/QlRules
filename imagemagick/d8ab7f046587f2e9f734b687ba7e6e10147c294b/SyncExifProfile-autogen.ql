/**
 * @name imagemagick-d8ab7f046587f2e9f734b687ba7e6e10147c294b-SyncExifProfile
 * @id cpp/imagemagick/d8ab7f046587f2e9f734b687ba7e6e10147c294b/SyncExifProfile
 * @description imagemagick-d8ab7f046587f2e9f734b687ba7e6e10147c294b-MagickCore/profile.c-SyncExifProfile CVE-2016-5841
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vlength_1925, Variable vexif_1938, Variable vq_2010, LogicalOrExpr target_2, RelationalOperation target_3, ExprStmt target_4, ExprStmt target_5, ExprStmt target_6) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vq_2010
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vexif_1938
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vlength_1925
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="12"
		and target_0.getThen().(BreakStmt).toString() = "break;"
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_3.getLesserOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_1(Variable vcomponents_2006, ExprStmt target_7, ExprStmt target_8) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcomponents_2006
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_1.getThen().(BreakStmt).toString() = "break;"
		and target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable vlength_1925, Variable vexif_1938, LogicalOrExpr target_2) {
		target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vexif_1938
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vexif_1938
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vlength_1925
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="2"
}

predicate func_3(Variable vlength_1925, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getLesserOperand().(VariableAccess).getTarget()=vlength_1925
}

predicate func_4(Variable vexif_1938, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vexif_1938
}

predicate func_5(Variable vq_2010, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vq_2010
		and target_5.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="2"
		and target_5.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(Literal).getValue()="12"
}

predicate func_6(Variable vq_2010, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ReadProfileShort")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vq_2010
}

predicate func_7(Variable vcomponents_2006, Variable vq_2010, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcomponents_2006
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ReadProfileLong")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vq_2010
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="4"
}

predicate func_8(Variable vcomponents_2006, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vcomponents_2006
}

from Function func, Variable vlength_1925, Variable vexif_1938, Variable vcomponents_2006, Variable vq_2010, LogicalOrExpr target_2, RelationalOperation target_3, ExprStmt target_4, ExprStmt target_5, ExprStmt target_6, ExprStmt target_7, ExprStmt target_8
where
not func_0(vlength_1925, vexif_1938, vq_2010, target_2, target_3, target_4, target_5, target_6)
and not func_1(vcomponents_2006, target_7, target_8)
and func_2(vlength_1925, vexif_1938, target_2)
and func_3(vlength_1925, target_3)
and func_4(vexif_1938, target_4)
and func_5(vq_2010, target_5)
and func_6(vq_2010, target_6)
and func_7(vcomponents_2006, vq_2010, target_7)
and func_8(vcomponents_2006, target_8)
and vlength_1925.getType().hasName("size_t")
and vexif_1938.getType().hasName("unsigned char *")
and vcomponents_2006.getType().hasName("int")
and vq_2010.getType().hasName("unsigned char *")
and vlength_1925.getParentScope+() = func
and vexif_1938.getParentScope+() = func
and vcomponents_2006.getParentScope+() = func
and vq_2010.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
