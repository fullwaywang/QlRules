/**
 * @name libjpeg-turbo-5bc43c7821df982f65aa1c738f67fbf7cba8bd69-read_and_discard_scanlines
 * @id cpp/libjpeg-turbo/5bc43c7821df982f65aa1c738f67fbf7cba8bd69/read-and-discard-scanlines
 * @description libjpeg-turbo-5bc43c7821df982f65aa1c738f67fbf7cba8bd69-jdapistd.c-read_and_discard_scanlines CVE-2017-15232
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vcinfo_305, ExprStmt target_2, ExprStmt target_3, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="cquantize"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_305
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="color_quantize"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cquantize"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_305
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("..(*)(..)")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="color_quantize"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cquantize"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_305
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="color_quantize"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cquantize"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_305
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_0)
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vcinfo_305, ExprStmt target_4, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(VariableAccess).getType().hasName("..(*)(..)")
		and target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="color_quantize"
		and target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cquantize"
		and target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_305
		and target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("..(*)(..)")
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_1)
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vcinfo_305, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="color_convert"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cconvert"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_305
}

predicate func_3(Parameter vcinfo_305, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("jpeg_read_scanlines")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcinfo_305
		and target_3.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_3.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="1"
}

predicate func_4(Parameter vcinfo_305, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="color_convert"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cconvert"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_305
}

from Function func, Parameter vcinfo_305, ExprStmt target_2, ExprStmt target_3, ExprStmt target_4
where
not func_0(vcinfo_305, target_2, target_3, func)
and not func_1(vcinfo_305, target_4, func)
and func_2(vcinfo_305, target_2)
and func_3(vcinfo_305, target_3)
and func_4(vcinfo_305, target_4)
and vcinfo_305.getType().hasName("j_decompress_ptr")
and vcinfo_305.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
