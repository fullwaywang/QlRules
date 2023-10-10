/**
 * @name openjpeg-820fcfe8bb101a2862c076b02c9b6b636ce39d2f-opj_tcd_update_tile_data
 * @id cpp/openjpeg/820fcfe8bb101a2862c076b02c9b6b636ce39d2f/opj-tcd-update-tile-data
 * @description openjpeg-820fcfe8bb101a2862c076b02c9b6b636ce39d2f-src/lib/openjp2/tcd.c-opj_tcd_update_tile_data CVE-2016-9581
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vl_src_ptr_1544, VariableAccess target_0) {
		target_0.getTarget()=vl_src_ptr_1544
}

predicate func_1(Variable vl_stride_1469, VariableAccess target_1) {
		target_1.getTarget()=vl_stride_1469
}

predicate func_2(Variable vk_1464, Variable vl_width_1469, BlockStmt target_19, RelationalOperation target_20, VariableAccess target_2) {
		target_2.getTarget()=vk_1464
		and target_2.getParent().(LTExpr).getGreaterOperand().(VariableAccess).getTarget()=vl_width_1469
		and target_2.getParent().(LTExpr).getParent().(ForStmt).getStmt()=target_19
		and target_20.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_2.getParent().(LTExpr).getGreaterOperand().(VariableAccess).getLocation())
}

predicate func_3(Variable vl_dest_ptr_1521) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("memcpy")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vl_dest_ptr_1521
		and target_3.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("OPJ_INT16")
		and target_3.getArgument(2).(SizeofExprOperator).getValue()="2")
}

predicate func_4(Variable vl_dest_ptr_1543) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("memcpy")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vl_dest_ptr_1543
		and target_4.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("OPJ_INT16")
		and target_4.getArgument(2).(SizeofExprOperator).getValue()="2")
}

predicate func_5(Variable vl_width_1469, Variable vl_dest_ptr_1543, Variable vl_src_ptr_1544, RelationalOperation target_20) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vl_dest_ptr_1543
		and target_5.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vl_src_ptr_1544
		and target_5.getExpr().(FunctionCall).getArgument(2).(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vl_width_1469
		and target_5.getExpr().(FunctionCall).getArgument(2).(MulExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_5.getExpr().(FunctionCall).getArgument(2).(MulExpr).getRightOperand().(SizeofTypeOperator).getValue()="4"
		and target_20.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_5.getExpr().(FunctionCall).getArgument(2).(MulExpr).getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_6(Variable vl_stride_1469, Variable vl_src_ptr_1544, ExprStmt target_24, ExprStmt target_25) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vl_src_ptr_1544
		and target_6.getExpr().(AssignPointerAddExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getType().hasName("OPJ_UINT32")
		and target_6.getExpr().(AssignPointerAddExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vl_stride_1469
		and target_24.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignPointerAddExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_6.getExpr().(AssignPointerAddExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_25.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_7(Variable vl_dest_ptr_1521, PostfixIncrExpr target_7) {
		target_7.getOperand().(VariableAccess).getTarget()=vl_dest_ptr_1521
}

predicate func_8(Variable vl_src_ptr_1520, PointerDereferenceExpr target_8) {
		target_8.getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vl_src_ptr_1520
		and target_8.getParent().(AssignExpr).getRValue() = target_8
		and target_8.getParent().(AssignExpr).getLValue() instanceof PointerDereferenceExpr
}

predicate func_9(Variable vl_dest_ptr_1521, PostfixIncrExpr target_9) {
		target_9.getOperand().(VariableAccess).getTarget()=vl_dest_ptr_1521
}

predicate func_10(Variable vl_src_ptr_1520, BitwiseAndExpr target_10) {
		target_10.getLeftOperand().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vl_src_ptr_1520
		and target_10.getRightOperand().(HexLiteral).getValue()="65535"
		and target_10.getParent().(AssignExpr).getRValue() = target_10
		and target_10.getParent().(AssignExpr).getLValue() instanceof PointerDereferenceExpr
}

predicate func_11(Variable vk_1464, Variable vl_width_1469, BlockStmt target_19, VariableAccess target_11) {
		target_11.getTarget()=vl_width_1469
		and target_11.getParent().(LTExpr).getLesserOperand().(VariableAccess).getTarget()=vk_1464
		and target_11.getParent().(LTExpr).getParent().(ForStmt).getStmt()=target_19
}

predicate func_12(Variable vl_src_ptr_1544, VariableAccess target_12) {
		target_12.getTarget()=vl_src_ptr_1544
}

predicate func_13(Function func, AssignExpr target_13) {
		target_13.getLValue().(PointerDereferenceExpr).getOperand() instanceof PostfixIncrExpr
		and target_13.getRValue() instanceof PointerDereferenceExpr
		and target_13.getEnclosingFunction() = func
}

predicate func_14(Function func, AssignExpr target_14) {
		target_14.getLValue().(PointerDereferenceExpr).getOperand() instanceof PostfixIncrExpr
		and target_14.getRValue() instanceof BitwiseAndExpr
		and target_14.getEnclosingFunction() = func
}

predicate func_15(Variable vk_1464, Variable vl_width_1469, Variable vl_dest_ptr_1543, Variable vl_src_ptr_1544, ForStmt target_15) {
		target_15.getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vk_1464
		and target_15.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_15.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vk_1464
		and target_15.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vl_width_1469
		and target_15.getUpdate().(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vk_1464
		and target_15.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vl_dest_ptr_1543
		and target_15.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vl_src_ptr_1544
}

/*predicate func_16(Variable vk_1464, PrefixIncrExpr target_26, AssignExpr target_16) {
		target_16.getLValue().(VariableAccess).getTarget()=vk_1464
		and target_16.getRValue().(Literal).getValue()="0"
		and target_26.getOperand().(VariableAccess).getLocation().isBefore(target_16.getLValue().(VariableAccess).getLocation())
}

*/
/*predicate func_17(Variable vl_dest_ptr_1543, Variable vl_src_ptr_1544, AssignExpr target_17) {
		target_17.getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vl_dest_ptr_1543
		and target_17.getRValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vl_src_ptr_1544
}

*/
predicate func_19(BlockStmt target_19) {
		target_19.getStmt(0).(ExprStmt).getExpr() instanceof AssignExpr
}

predicate func_20(Variable vk_1464, Variable vl_width_1469, RelationalOperation target_20) {
		 (target_20 instanceof GTExpr or target_20 instanceof LTExpr)
		and target_20.getLesserOperand().(VariableAccess).getTarget()=vk_1464
		and target_20.getGreaterOperand().(VariableAccess).getTarget()=vl_width_1469
}

predicate func_24(Variable vl_stride_1469, Variable vl_src_ptr_1520, ExprStmt target_24) {
		target_24.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vl_src_ptr_1520
		and target_24.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vl_stride_1469
}

predicate func_25(Variable vl_stride_1469, Variable vl_src_ptr_1544, ExprStmt target_25) {
		target_25.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vl_src_ptr_1544
		and target_25.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vl_stride_1469
}

predicate func_26(Variable vk_1464, PrefixIncrExpr target_26) {
		target_26.getOperand().(VariableAccess).getTarget()=vk_1464
}

from Function func, Variable vk_1464, Variable vl_stride_1469, Variable vl_width_1469, Variable vl_src_ptr_1520, Variable vl_dest_ptr_1521, Variable vl_dest_ptr_1543, Variable vl_src_ptr_1544, VariableAccess target_0, VariableAccess target_1, VariableAccess target_2, PostfixIncrExpr target_7, PointerDereferenceExpr target_8, PostfixIncrExpr target_9, BitwiseAndExpr target_10, VariableAccess target_11, VariableAccess target_12, AssignExpr target_13, AssignExpr target_14, ForStmt target_15, BlockStmt target_19, RelationalOperation target_20, ExprStmt target_24, ExprStmt target_25, PrefixIncrExpr target_26
where
func_0(vl_src_ptr_1544, target_0)
and func_1(vl_stride_1469, target_1)
and func_2(vk_1464, vl_width_1469, target_19, target_20, target_2)
and not func_3(vl_dest_ptr_1521)
and not func_4(vl_dest_ptr_1543)
and not func_5(vl_width_1469, vl_dest_ptr_1543, vl_src_ptr_1544, target_20)
and not func_6(vl_stride_1469, vl_src_ptr_1544, target_24, target_25)
and func_7(vl_dest_ptr_1521, target_7)
and func_8(vl_src_ptr_1520, target_8)
and func_9(vl_dest_ptr_1521, target_9)
and func_10(vl_src_ptr_1520, target_10)
and func_11(vk_1464, vl_width_1469, target_19, target_11)
and func_12(vl_src_ptr_1544, target_12)
and func_13(func, target_13)
and func_14(func, target_14)
and func_15(vk_1464, vl_width_1469, vl_dest_ptr_1543, vl_src_ptr_1544, target_15)
and func_19(target_19)
and func_20(vk_1464, vl_width_1469, target_20)
and func_24(vl_stride_1469, vl_src_ptr_1520, target_24)
and func_25(vl_stride_1469, vl_src_ptr_1544, target_25)
and func_26(vk_1464, target_26)
and vk_1464.getType().hasName("OPJ_UINT32")
and vl_stride_1469.getType().hasName("OPJ_UINT32")
and vl_width_1469.getType().hasName("OPJ_UINT32")
and vl_src_ptr_1520.getType().hasName("const OPJ_INT32 *")
and vl_dest_ptr_1521.getType().hasName("OPJ_INT16 *")
and vl_dest_ptr_1543.getType().hasName("OPJ_INT32 *")
and vl_src_ptr_1544.getType().hasName("OPJ_INT32 *")
and vk_1464.getParentScope+() = func
and vl_stride_1469.getParentScope+() = func
and vl_width_1469.getParentScope+() = func
and vl_src_ptr_1520.getParentScope+() = func
and vl_dest_ptr_1521.getParentScope+() = func
and vl_dest_ptr_1543.getParentScope+() = func
and vl_src_ptr_1544.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
