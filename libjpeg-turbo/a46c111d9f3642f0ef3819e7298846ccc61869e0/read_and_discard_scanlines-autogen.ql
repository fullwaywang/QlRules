/**
 * @name libjpeg-turbo-a46c111d9f3642f0ef3819e7298846ccc61869e0-read_and_discard_scanlines
 * @id cpp/libjpeg-turbo/a46c111d9f3642f0ef3819e7298846ccc61869e0/read-and-discard-scanlines
 * @description libjpeg-turbo-a46c111d9f3642f0ef3819e7298846ccc61869e0-jdapistd.c-read_and_discard_scanlines CVE-2020-35538
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Initializer target_0) {
		target_0.getExpr().(Literal).getValue()="0"
		and target_0.getExpr().getEnclosingFunction() = func
}

predicate func_1(Parameter vcinfo_328, Literal target_1) {
		target_1.getValue()="0"
		and not target_1.getValue()="2"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("jpeg_read_scanlines")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcinfo_328
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="1"
}

predicate func_3(Parameter vcinfo_328, BlockStmt target_15, ExprStmt target_16, LogicalAndExpr target_17) {
	exists(EqualityOperation target_3 |
		target_3.getAnOperand().(PointerFieldAccess).getTarget().getName()="max_v_samp_factor"
		and target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_328
		and target_3.getAnOperand().(Literal).getValue()="2"
		and target_3.getParent().(LogicalAndExpr).getAnOperand() instanceof LogicalAndExpr
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="post_process_data"
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="post"
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_328
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_15
		and target_16.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_17.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_4(Function func) {
	exists(AssignExpr target_4 |
		target_4.getLValue().(VariableAccess).getType().hasName("JSAMPARRAY")
		and target_4.getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="spare_row"
		and target_4.getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("my_merged_upsample_ptr")
		and target_4.getEnclosingFunction() = func)
}

predicate func_6(Variable vmaster_331, PointerFieldAccess target_6) {
		target_6.getTarget().getName()="using_merged_upsample"
		and target_6.getQualifier().(VariableAccess).getTarget()=vmaster_331
}

predicate func_7(Parameter vcinfo_328, VariableAccess target_7) {
		target_7.getTarget()=vcinfo_328
}

predicate func_8(Parameter vcinfo_328, VariableAccess target_8) {
		target_8.getTarget()=vcinfo_328
}

predicate func_10(Parameter vcinfo_328, Variable vmaster_331, BlockStmt target_15, LogicalAndExpr target_10) {
		target_10.getAnOperand().(PointerFieldAccess).getTarget().getName()="using_merged_upsample"
		and target_10.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmaster_331
		and target_10.getAnOperand().(PointerFieldAccess).getTarget().getName()="post"
		and target_10.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_328
		and target_10.getParent().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="post_process_data"
		and target_10.getParent().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="post"
		and target_10.getParent().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_328
		and target_10.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_15
}

/*predicate func_11(Parameter vcinfo_328, LogicalAndExpr target_17, PointerFieldAccess target_11) {
		target_11.getTarget().getName()="post_process_data"
		and target_11.getQualifier().(PointerFieldAccess).getTarget().getName()="post"
		and target_11.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_328
		and target_17.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_11.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

*/
predicate func_12(Parameter vcinfo_328, Variable vpost_process_data_337, AssignExpr target_12) {
		target_12.getLValue().(VariableAccess).getTarget()=vpost_process_data_337
		and target_12.getRValue().(PointerFieldAccess).getTarget().getName()="post_process_data"
		and target_12.getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="post"
		and target_12.getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_328
}

predicate func_13(Parameter vcinfo_328, LogicalAndExpr target_17, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="post_process_data"
		and target_13.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="post"
		and target_13.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_328
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_17
}

predicate func_14(Parameter vcinfo_328, Variable vpost_process_data_337, Function func, IfStmt target_14) {
		target_14.getCondition().(VariableAccess).getTarget()=vpost_process_data_337
		and target_14.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="post_process_data"
		and target_14.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="post"
		and target_14.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_328
		and target_14.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vpost_process_data_337
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_14
}

predicate func_15(BlockStmt target_15) {
		target_15.getStmt(0).(ExprStmt).getExpr() instanceof AssignExpr
		and target_15.getStmt(1) instanceof ExprStmt
}

predicate func_16(Parameter vcinfo_328, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="color_quantize"
		and target_16.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cquantize"
		and target_16.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_328
}

predicate func_17(Parameter vcinfo_328, LogicalAndExpr target_17) {
		target_17.getAnOperand() instanceof LogicalAndExpr
		and target_17.getAnOperand().(PointerFieldAccess).getTarget().getName()="post_process_data"
		and target_17.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="post"
		and target_17.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_328
}

from Function func, Parameter vcinfo_328, Variable vmaster_331, Variable vpost_process_data_337, Initializer target_0, Literal target_1, PointerFieldAccess target_6, VariableAccess target_7, VariableAccess target_8, LogicalAndExpr target_10, AssignExpr target_12, ExprStmt target_13, IfStmt target_14, BlockStmt target_15, ExprStmt target_16, LogicalAndExpr target_17
where
func_0(func, target_0)
and func_1(vcinfo_328, target_1)
and not func_3(vcinfo_328, target_15, target_16, target_17)
and not func_4(func)
and func_6(vmaster_331, target_6)
and func_7(vcinfo_328, target_7)
and func_8(vcinfo_328, target_8)
and func_10(vcinfo_328, vmaster_331, target_15, target_10)
and func_12(vcinfo_328, vpost_process_data_337, target_12)
and func_13(vcinfo_328, target_17, target_13)
and func_14(vcinfo_328, vpost_process_data_337, func, target_14)
and func_15(target_15)
and func_16(vcinfo_328, target_16)
and func_17(vcinfo_328, target_17)
and vcinfo_328.getType().hasName("j_decompress_ptr")
and vmaster_331.getType().hasName("my_master_ptr")
and vpost_process_data_337.getType().hasName("..(*)(..)")
and vcinfo_328.getParentScope+() = func
and vmaster_331.getParentScope+() = func
and vpost_process_data_337.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
