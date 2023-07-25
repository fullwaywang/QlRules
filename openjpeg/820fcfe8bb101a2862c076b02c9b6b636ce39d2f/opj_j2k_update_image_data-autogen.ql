/**
 * @name openjpeg-820fcfe8bb101a2862c076b02c9b6b636ce39d2f-opj_j2k_update_image_data
 * @id cpp/openjpeg/820fcfe8bb101a2862c076b02c9b6b636ce39d2f/opj-j2k-update-image-data
 * @description openjpeg-820fcfe8bb101a2862c076b02c9b6b636ce39d2f-src/lib/openjp2/j2k.c-opj_j2k_update_image_data CVE-2016-9581
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vk_8737, Variable vl_width_dest_8739, BlockStmt target_20, RelationalOperation target_21, VariableAccess target_0) {
		target_0.getTarget()=vk_8737
		and target_0.getParent().(LTExpr).getGreaterOperand().(VariableAccess).getTarget()=vl_width_dest_8739
		and target_0.getParent().(LTExpr).getParent().(ForStmt).getStmt()=target_20
		and target_21.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_0.getParent().(LTExpr).getGreaterOperand().(VariableAccess).getLocation())
}

predicate func_1(Variable vl_src_ptr_8948, ExprStmt target_22) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("memcpy")
		and target_1.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("OPJ_INT16")
		and target_1.getArgument(1).(VariableAccess).getTarget()=vl_src_ptr_8948
		and target_1.getArgument(2).(SizeofExprOperator).getValue()="2"
		and target_22.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getArgument(1).(VariableAccess).getLocation()))
}

predicate func_3(Variable vl_src_ptr_8976, ExprStmt target_25) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("memcpy")
		and target_3.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("OPJ_INT16")
		and target_3.getArgument(1).(VariableAccess).getTarget()=vl_src_ptr_8976
		and target_3.getArgument(2).(SizeofExprOperator).getValue()="2"
		and target_3.getArgument(1).(VariableAccess).getLocation().isBefore(target_25.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_5(Variable vl_width_dest_8739, Variable vl_dest_ptr_8752, Variable vl_src_ptr_8976, RelationalOperation target_21, ExprStmt target_26, ExprStmt target_28) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vl_dest_ptr_8752
		and target_5.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vl_src_ptr_8976
		and target_5.getExpr().(FunctionCall).getArgument(2).(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vl_width_dest_8739
		and target_5.getExpr().(FunctionCall).getArgument(2).(MulExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_5.getExpr().(FunctionCall).getArgument(2).(MulExpr).getRightOperand().(SizeofTypeOperator).getValue()="4"
		and target_21.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_5.getExpr().(FunctionCall).getArgument(2).(MulExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_26.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_28.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_5.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_6(Variable vl_line_offset_dest_8744, Variable vl_dest_ptr_8752, ExprStmt target_26) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vl_dest_ptr_8752
		and target_6.getExpr().(AssignPointerAddExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getType().hasName("OPJ_UINT32")
		and target_6.getExpr().(AssignPointerAddExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vl_line_offset_dest_8744
		and target_26.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignPointerAddExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getLocation()))
}

/*predicate func_7(Variable vl_line_offset_dest_8744, ExprStmt target_26) {
	exists(AddExpr target_7 |
		target_7.getAnOperand().(VariableAccess).getType().hasName("OPJ_UINT32")
		and target_7.getAnOperand().(VariableAccess).getTarget()=vl_line_offset_dest_8744
		and target_26.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getLocation().isBefore(target_7.getAnOperand().(VariableAccess).getLocation()))
}

*/
predicate func_8(Variable vl_width_dest_8739, Variable vl_line_offset_src_8741, Variable vl_src_ptr_8976, RelationalOperation target_31, ExprStmt target_32, ExprStmt target_33) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vl_src_ptr_8976
		and target_8.getExpr().(AssignPointerAddExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vl_width_dest_8739
		and target_8.getExpr().(AssignPointerAddExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vl_line_offset_src_8741
		and target_31.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignPointerAddExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_32.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignPointerAddExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_8.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_33.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation()))
}

/*predicate func_9(Variable vl_width_dest_8739, Variable vl_line_offset_src_8741, RelationalOperation target_31, ExprStmt target_32) {
	exists(AddExpr target_9 |
		target_9.getAnOperand().(VariableAccess).getTarget()=vl_width_dest_8739
		and target_9.getAnOperand().(VariableAccess).getTarget()=vl_line_offset_src_8741
		and target_31.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_9.getAnOperand().(VariableAccess).getLocation())
		and target_32.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getLocation().isBefore(target_9.getAnOperand().(VariableAccess).getLocation()))
}

*/
predicate func_10(Variable vl_src_ptr_8948, PostfixIncrExpr target_10) {
		target_10.getOperand().(VariableAccess).getTarget()=vl_src_ptr_8948
}

predicate func_11(Variable vl_src_ptr_8948, PostfixIncrExpr target_11) {
		target_11.getOperand().(VariableAccess).getTarget()=vl_src_ptr_8948
}

predicate func_12(Variable vk_8737, Variable vl_width_dest_8739, BlockStmt target_20, VariableAccess target_12) {
		target_12.getTarget()=vl_width_dest_8739
		and target_12.getParent().(LTExpr).getLesserOperand().(VariableAccess).getTarget()=vk_8737
		and target_12.getParent().(LTExpr).getParent().(ForStmt).getStmt()=target_20
}

predicate func_13(Variable vl_line_offset_dest_8744, VariableAccess target_13) {
		target_13.getTarget()=vl_line_offset_dest_8744
}

predicate func_14(Variable vl_line_offset_src_8741, VariableAccess target_14) {
		target_14.getTarget()=vl_line_offset_src_8741
}

predicate func_15(Variable vl_dest_ptr_8752, ExprStmt target_34, ExprStmt target_35, PointerDereferenceExpr target_15) {
		target_15.getOperand() instanceof PostfixIncrExpr
		and target_15.getParent().(AssignExpr).getRValue() = target_15
		and target_15.getParent().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vl_dest_ptr_8752
		and target_34.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_15.getParent().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation())
		and target_15.getParent().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_35.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation())
}

predicate func_16(Function func, PointerDereferenceExpr target_16) {
		target_16.getOperand() instanceof PostfixIncrExpr
		and target_16.getEnclosingFunction() = func
}

predicate func_17(Variable vk_8737, Variable vl_width_dest_8739, Variable vl_dest_ptr_8752, Variable vl_src_ptr_8976, ForStmt target_17) {
		target_17.getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vk_8737
		and target_17.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_17.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vk_8737
		and target_17.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vl_width_dest_8739
		and target_17.getUpdate().(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vk_8737
		and target_17.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vl_dest_ptr_8752
		and target_17.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vl_src_ptr_8976
}

/*predicate func_18(Variable vk_8737, PrefixIncrExpr target_36, AssignExpr target_18) {
		target_18.getLValue().(VariableAccess).getTarget()=vk_8737
		and target_18.getRValue().(Literal).getValue()="0"
		and target_36.getOperand().(VariableAccess).getLocation().isBefore(target_18.getLValue().(VariableAccess).getLocation())
}

*/
/*predicate func_19(Variable vl_dest_ptr_8752, Variable vl_src_ptr_8976, AssignExpr target_19) {
		target_19.getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vl_dest_ptr_8752
		and target_19.getRValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vl_src_ptr_8976
}

*/
predicate func_20(BlockStmt target_20) {
		target_20.getStmt(0).(ExprStmt).getExpr() instanceof AssignExpr
}

predicate func_21(Variable vk_8737, Variable vl_width_dest_8739, RelationalOperation target_21) {
		 (target_21 instanceof GTExpr or target_21 instanceof LTExpr)
		and target_21.getLesserOperand().(VariableAccess).getTarget()=vk_8737
		and target_21.getGreaterOperand().(VariableAccess).getTarget()=vl_width_dest_8739
}

predicate func_22(Variable vl_src_ptr_8948, ExprStmt target_22) {
		target_22.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vl_src_ptr_8948
}

predicate func_25(Variable vl_line_offset_src_8741, Variable vl_src_ptr_8976, ExprStmt target_25) {
		target_25.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vl_src_ptr_8976
		and target_25.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vl_line_offset_src_8741
}

predicate func_26(Variable vl_line_offset_dest_8744, Variable vl_dest_ptr_8752, ExprStmt target_26) {
		target_26.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vl_dest_ptr_8752
		and target_26.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vl_line_offset_dest_8744
}

predicate func_28(Variable vl_src_ptr_8976, ExprStmt target_28) {
		target_28.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vl_src_ptr_8976
}

predicate func_31(Variable vk_8737, Variable vl_width_dest_8739, RelationalOperation target_31) {
		 (target_31 instanceof GTExpr or target_31 instanceof LTExpr)
		and target_31.getLesserOperand().(VariableAccess).getTarget()=vk_8737
		and target_31.getGreaterOperand().(VariableAccess).getTarget()=vl_width_dest_8739
}

predicate func_32(Variable vl_line_offset_src_8741, Variable vl_src_ptr_8948, ExprStmt target_32) {
		target_32.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vl_src_ptr_8948
		and target_32.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vl_line_offset_src_8741
}

predicate func_33(Variable vl_src_ptr_8976, ExprStmt target_33) {
		target_33.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vl_src_ptr_8976
}

predicate func_34(Variable vl_line_offset_dest_8744, Variable vl_dest_ptr_8752, ExprStmt target_34) {
		target_34.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vl_dest_ptr_8752
		and target_34.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vl_line_offset_dest_8744
}

predicate func_35(Variable vl_line_offset_dest_8744, Variable vl_dest_ptr_8752, ExprStmt target_35) {
		target_35.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vl_dest_ptr_8752
		and target_35.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vl_line_offset_dest_8744
}

predicate func_36(Variable vk_8737, PrefixIncrExpr target_36) {
		target_36.getOperand().(VariableAccess).getTarget()=vk_8737
}

from Function func, Variable vk_8737, Variable vl_width_dest_8739, Variable vl_line_offset_src_8741, Variable vl_line_offset_dest_8744, Variable vl_dest_ptr_8752, Variable vl_src_ptr_8948, Variable vl_src_ptr_8976, VariableAccess target_0, PostfixIncrExpr target_10, PostfixIncrExpr target_11, VariableAccess target_12, VariableAccess target_13, VariableAccess target_14, PointerDereferenceExpr target_15, PointerDereferenceExpr target_16, ForStmt target_17, BlockStmt target_20, RelationalOperation target_21, ExprStmt target_22, ExprStmt target_25, ExprStmt target_26, ExprStmt target_28, RelationalOperation target_31, ExprStmt target_32, ExprStmt target_33, ExprStmt target_34, ExprStmt target_35, PrefixIncrExpr target_36
where
func_0(vk_8737, vl_width_dest_8739, target_20, target_21, target_0)
and not func_1(vl_src_ptr_8948, target_22)
and not func_3(vl_src_ptr_8976, target_25)
and not func_5(vl_width_dest_8739, vl_dest_ptr_8752, vl_src_ptr_8976, target_21, target_26, target_28)
and not func_6(vl_line_offset_dest_8744, vl_dest_ptr_8752, target_26)
and not func_8(vl_width_dest_8739, vl_line_offset_src_8741, vl_src_ptr_8976, target_31, target_32, target_33)
and func_10(vl_src_ptr_8948, target_10)
and func_11(vl_src_ptr_8948, target_11)
and func_12(vk_8737, vl_width_dest_8739, target_20, target_12)
and func_13(vl_line_offset_dest_8744, target_13)
and func_14(vl_line_offset_src_8741, target_14)
and func_15(vl_dest_ptr_8752, target_34, target_35, target_15)
and func_16(func, target_16)
and func_17(vk_8737, vl_width_dest_8739, vl_dest_ptr_8752, vl_src_ptr_8976, target_17)
and func_20(target_20)
and func_21(vk_8737, vl_width_dest_8739, target_21)
and func_22(vl_src_ptr_8948, target_22)
and func_25(vl_line_offset_src_8741, vl_src_ptr_8976, target_25)
and func_26(vl_line_offset_dest_8744, vl_dest_ptr_8752, target_26)
and func_28(vl_src_ptr_8976, target_28)
and func_31(vk_8737, vl_width_dest_8739, target_31)
and func_32(vl_line_offset_src_8741, vl_src_ptr_8948, target_32)
and func_33(vl_src_ptr_8976, target_33)
and func_34(vl_line_offset_dest_8744, vl_dest_ptr_8752, target_34)
and func_35(vl_line_offset_dest_8744, vl_dest_ptr_8752, target_35)
and func_36(vk_8737, target_36)
and vk_8737.getType().hasName("OPJ_UINT32")
and vl_width_dest_8739.getType().hasName("OPJ_UINT32")
and vl_line_offset_src_8741.getType().hasName("OPJ_SIZE_T")
and vl_line_offset_dest_8744.getType().hasName("OPJ_SIZE_T")
and vl_dest_ptr_8752.getType().hasName("OPJ_INT32 *")
and vl_src_ptr_8948.getType().hasName("OPJ_INT16 *")
and vl_src_ptr_8976.getType().hasName("OPJ_INT32 *")
and vk_8737.getParentScope+() = func
and vl_width_dest_8739.getParentScope+() = func
and vl_line_offset_src_8741.getParentScope+() = func
and vl_line_offset_dest_8744.getParentScope+() = func
and vl_dest_ptr_8752.getParentScope+() = func
and vl_src_ptr_8948.getParentScope+() = func
and vl_src_ptr_8976.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
