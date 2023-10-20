/**
 * @name libexif-5ae5973bed1947f4d447dc80b76d5cefadd90133-exif_data_save_data_entry
 * @id cpp/libexif/5ae5973bed1947f4d447dc80b76d5cefadd90133/exif-data-save-data-entry
 * @description libexif-5ae5973bed1947f4d447dc80b76d5cefadd90133-libexif/exif-data.c-exif_data_save_data_entry CVE-2020-0093
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter ve_236, Variable vs_240, VariableAccess target_0) {
		target_0.getTarget()=vs_240
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="6"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="data"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ve_236
}

predicate func_1(Parameter ve_236, Variable vs_240, PointerFieldAccess target_2, IfStmt target_3, ExprStmt target_4) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ve_236
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vs_240
		and target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("unsigned int")
		and target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="size"
		and target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ve_236
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_3.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter ve_236, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="data"
		and target_2.getQualifier().(VariableAccess).getTarget()=ve_236
}

predicate func_3(Parameter ve_236, Variable vs_240, IfStmt target_3) {
		target_3.getCondition().(PointerFieldAccess).getTarget().getName()="data"
		and target_3.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ve_236
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="6"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="data"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ve_236
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vs_240
		and target_3.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memset")
		and target_3.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="6"
		and target_3.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_3.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vs_240
}

predicate func_4(Parameter ve_236, Variable vs_240, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="6"
		and target_4.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="data"
		and target_4.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ve_236
		and target_4.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vs_240
}

from Function func, Parameter ve_236, Variable vs_240, VariableAccess target_0, PointerFieldAccess target_2, IfStmt target_3, ExprStmt target_4
where
func_0(ve_236, vs_240, target_0)
and not func_1(ve_236, vs_240, target_2, target_3, target_4)
and func_2(ve_236, target_2)
and func_3(ve_236, vs_240, target_3)
and func_4(ve_236, vs_240, target_4)
and ve_236.getType().hasName("ExifEntry *")
and vs_240.getType().hasName("unsigned int")
and ve_236.getParentScope+() = func
and vs_240.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
