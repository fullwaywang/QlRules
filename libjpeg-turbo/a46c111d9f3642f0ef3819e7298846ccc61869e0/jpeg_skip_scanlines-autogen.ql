/**
 * @name libjpeg-turbo-a46c111d9f3642f0ef3819e7298846ccc61869e0-jpeg_skip_scanlines
 * @id cpp/libjpeg-turbo/a46c111d9f3642f0ef3819e7298846ccc61869e0/jpeg-skip-scanlines
 * @description libjpeg-turbo-a46c111d9f3642f0ef3819e7298846ccc61869e0-jdapistd.c-jpeg_skip_scanlines CVE-2020-35538
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vcinfo_408, BlockStmt target_48, ExprStmt target_12, ExprStmt target_16) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(PointerFieldAccess).getTarget().getName()="quantize_colors"
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_408
		and target_0.getAnOperand().(PointerFieldAccess).getTarget().getName()="two_pass_quantize"
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_408
		and target_0.getParent().(IfStmt).getThen()=target_48
		and target_12.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_16.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vcinfo_408, ExprStmt target_49, ExprStmt target_46) {
	exists(CommaExpr target_1 |
		target_1.getLeftOperand().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="msg_code"
		and target_1.getLeftOperand().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="err"
		and target_1.getLeftOperand().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_408
		and target_1.getRightOperand().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="error_exit"
		and target_1.getRightOperand().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="err"
		and target_1.getRightOperand().(ExprCall).getExpr().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_408
		and target_1.getRightOperand().(ExprCall).getArgument(0).(VariableAccess).getTarget()=vcinfo_408
		and target_49.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getLeftOperand().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getLeftOperand().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_46.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vmaster_412, BlockStmt target_50, IfStmt target_51) {
	exists(NotExpr target_2 |
		target_2.getOperand().(PointerFieldAccess).getTarget().getName()="using_merged_upsample"
		and target_2.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmaster_412
		and target_2.getParent().(IfStmt).getThen()=target_50
		and target_2.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_51.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Variable vmaster_412, BlockStmt target_52, IfStmt target_53, IfStmt target_54) {
	exists(NotExpr target_3 |
		target_3.getOperand().(PointerFieldAccess).getTarget().getName()="using_merged_upsample"
		and target_3.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmaster_412
		and target_3.getParent().(IfStmt).getThen()=target_52
		and target_53.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_54.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_4(Variable vmaster_412, BlockStmt target_55, IfStmt target_51, IfStmt target_56) {
	exists(NotExpr target_4 |
		target_4.getOperand().(PointerFieldAccess).getTarget().getName()="using_merged_upsample"
		and target_4.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmaster_412
		and target_4.getParent().(IfStmt).getThen()=target_55
		and target_51.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_56.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_5(Variable vmaster_412, IfStmt target_54, Function func) {
	exists(IfStmt target_5 |
		target_5.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="using_merged_upsample"
		and target_5.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmaster_412
		and target_5.getThen() instanceof ExprStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(22)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(22).getFollowingStmt()=target_5)
		and target_54.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_6(Parameter vcinfo_408, BlockStmt target_48, PointerFieldAccess target_6) {
		target_6.getTarget().getName()="need_context_rows"
		and target_6.getQualifier().(PointerFieldAccess).getTarget().getName()="upsample"
		and target_6.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_408
		and target_6.getParent().(IfStmt).getThen()=target_48
}

predicate func_7(Parameter vcinfo_408, PointerFieldAccess target_7) {
		target_7.getTarget().getName()="upsample"
		and target_7.getQualifier().(VariableAccess).getTarget()=vcinfo_408
}

predicate func_8(Variable vupsample_476, Parameter vcinfo_408, SubExpr target_8) {
		target_8.getLeftOperand().(PointerFieldAccess).getTarget().getName()="output_height"
		and target_8.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_408
		and target_8.getRightOperand().(PointerFieldAccess).getTarget().getName()="output_scanline"
		and target_8.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_408
		and target_8.getParent().(AssignExpr).getRValue() = target_8
		and target_8.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="rows_to_go"
		and target_8.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vupsample_476
}

predicate func_9(Variable vupsample_481, Parameter vcinfo_408, PointerFieldAccess target_23, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="next_row_out"
		and target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vupsample_481
		and target_9.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="max_v_samp_factor"
		and target_9.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_408
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_23
}

predicate func_10(Variable vupsample_481, Parameter vcinfo_408, PointerFieldAccess target_23, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="rows_to_go"
		and target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vupsample_481
		and target_10.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="output_height"
		and target_10.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_408
		and target_10.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="output_scanline"
		and target_10.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_408
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_23
}

predicate func_11(Variable vlines_left_in_iMCU_row_415, Parameter vnum_lines_408, BlockStmt target_50, RelationalOperation target_11) {
		 (target_11 instanceof GTExpr or target_11 instanceof LTExpr)
		and target_11.getLesserOperand().(VariableAccess).getTarget()=vnum_lines_408
		and target_11.getGreaterOperand().(VariableAccess).getTarget()=vlines_left_in_iMCU_row_415
		and target_11.getParent().(IfStmt).getThen()=target_50
}

predicate func_12(Variable vlines_left_in_iMCU_row_415, Parameter vcinfo_408, RelationalOperation target_11, ExprStmt target_12) {
		target_12.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="output_scanline"
		and target_12.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_408
		and target_12.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vlines_left_in_iMCU_row_415
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_13(Variable vmain_ptr_410, RelationalOperation target_11, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="buffer_full"
		and target_13.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmain_ptr_410
		and target_13.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_14(Variable vmain_ptr_410, RelationalOperation target_11, ExprStmt target_14) {
		target_14.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="rowgroup_ctr"
		and target_14.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmain_ptr_410
		and target_14.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_14.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
}

predicate func_15(Variable vupsample_497, Parameter vcinfo_408, SubExpr target_15) {
		target_15.getLeftOperand().(PointerFieldAccess).getTarget().getName()="output_height"
		and target_15.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_408
		and target_15.getRightOperand().(PointerFieldAccess).getTarget().getName()="output_scanline"
		and target_15.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_408
		and target_15.getParent().(AssignExpr).getRValue() = target_15
		and target_15.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="rows_to_go"
		and target_15.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vupsample_497
}

predicate func_16(Variable vupsample_502, Parameter vcinfo_408, PointerFieldAccess target_25, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="next_row_out"
		and target_16.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vupsample_502
		and target_16.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="max_v_samp_factor"
		and target_16.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_408
		and target_16.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_25
}

predicate func_17(Variable vupsample_502, Parameter vcinfo_408, PointerFieldAccess target_25, ExprStmt target_17) {
		target_17.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="rows_to_go"
		and target_17.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vupsample_502
		and target_17.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="output_height"
		and target_17.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_408
		and target_17.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="output_scanline"
		and target_17.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_408
		and target_17.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_25
}

predicate func_18(Parameter vcinfo_408, BlockStmt target_52, PointerFieldAccess target_18) {
		target_18.getTarget().getName()="has_multiple_scans"
		and target_18.getQualifier().(PointerFieldAccess).getTarget().getName()="inputctl"
		and target_18.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_408
		and target_18.getParent().(IfStmt).getThen()=target_52
}

predicate func_19(Variable vmain_ptr_410, Variable vlines_per_iMCU_row_415, Variable vlines_to_skip_416, Variable vlines_to_read_416, Parameter vcinfo_408, PointerFieldAccess target_18, IfStmt target_19) {
		target_19.getCondition().(PointerFieldAccess).getTarget().getName()="need_context_rows"
		and target_19.getCondition().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="upsample"
		and target_19.getCondition().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_408
		and target_19.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="output_scanline"
		and target_19.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_408
		and target_19.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vlines_to_skip_416
		and target_19.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="output_iMCU_row"
		and target_19.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_408
		and target_19.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vlines_to_skip_416
		and target_19.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(DivExpr).getRightOperand().(VariableAccess).getTarget()=vlines_per_iMCU_row_415
		and target_19.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="iMCU_row_ctr"
		and target_19.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmain_ptr_410
		and target_19.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vlines_to_skip_416
		and target_19.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(DivExpr).getRightOperand().(VariableAccess).getTarget()=vlines_per_iMCU_row_415
		and target_19.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("read_and_discard_scanlines")
		and target_19.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcinfo_408
		and target_19.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vlines_to_read_416
		and target_19.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="output_scanline"
		and target_19.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_408
		and target_19.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vlines_to_skip_416
		and target_19.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="output_iMCU_row"
		and target_19.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_408
		and target_19.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vlines_to_skip_416
		and target_19.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(DivExpr).getRightOperand().(VariableAccess).getTarget()=vlines_per_iMCU_row_415
		and target_19.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("increment_simple_rowgroup_ctr")
		and target_19.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcinfo_408
		and target_19.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vlines_to_read_416
		and target_19.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_18
}

predicate func_20(Parameter vcinfo_408, Variable vupsample_541, SubExpr target_20) {
		target_20.getLeftOperand().(PointerFieldAccess).getTarget().getName()="output_height"
		and target_20.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_408
		and target_20.getRightOperand().(PointerFieldAccess).getTarget().getName()="output_scanline"
		and target_20.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_408
		and target_20.getParent().(AssignExpr).getRValue() = target_20
		and target_20.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="rows_to_go"
		and target_20.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vupsample_541
}

/*predicate func_21(Parameter vcinfo_408, Variable vupsample_545, SubExpr target_21) {
		target_21.getLeftOperand().(PointerFieldAccess).getTarget().getName()="output_height"
		and target_21.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_408
		and target_21.getRightOperand().(PointerFieldAccess).getTarget().getName()="output_scanline"
		and target_21.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_408
		and target_21.getParent().(AssignExpr).getRValue() = target_21
		and target_21.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="rows_to_go"
		and target_21.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vupsample_545
}

*/
predicate func_22(Parameter vnum_lines_408, PointerFieldAccess target_18, ReturnStmt target_22) {
		target_22.getExpr().(VariableAccess).getTarget()=vnum_lines_408
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_18
}

predicate func_23(Variable vmaster_412, BlockStmt target_57, PointerFieldAccess target_23) {
		target_23.getTarget().getName()="using_merged_upsample"
		and target_23.getQualifier().(VariableAccess).getTarget()=vmaster_412
		and target_23.getParent().(IfStmt).getThen()=target_57
}

predicate func_24(PointerFieldAccess target_23, Function func, DeclStmt target_24) {
		target_24.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_23
		and target_24.getEnclosingFunction() = func
}

predicate func_25(Variable vmaster_412, BlockStmt target_58, PointerFieldAccess target_25) {
		target_25.getTarget().getName()="using_merged_upsample"
		and target_25.getQualifier().(VariableAccess).getTarget()=vmaster_412
		and target_25.getParent().(IfStmt).getThen()=target_58
}

predicate func_26(Variable vmaster_412, BlockStmt target_55, PointerFieldAccess target_26) {
		target_26.getTarget().getName()="using_merged_upsample"
		and target_26.getQualifier().(VariableAccess).getTarget()=vmaster_412
		and target_26.getParent().(IfStmt).getThen()=target_55
}

predicate func_27(Parameter vcinfo_408, Variable vupsample_545, PointerFieldAccess target_26, ExprStmt target_27) {
		target_27.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="rows_to_go"
		and target_27.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vupsample_545
		and target_27.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="output_height"
		and target_27.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_408
		and target_27.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="output_scanline"
		and target_27.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_408
		and target_27.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_26
}

predicate func_28(Variable vmaster_412, BlockStmt target_59, PointerFieldAccess target_28) {
		target_28.getTarget().getName()="using_merged_upsample"
		and target_28.getQualifier().(VariableAccess).getTarget()=vmaster_412
		and target_28.getParent().(IfStmt).getThen()=target_59
}

predicate func_29(Parameter vcinfo_408, Variable vupsample_592, PointerFieldAccess target_28, ExprStmt target_29) {
		target_29.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="rows_to_go"
		and target_29.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vupsample_592
		and target_29.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="output_height"
		and target_29.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_408
		and target_29.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="output_scanline"
		and target_29.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_408
		and target_29.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_28
}

predicate func_30(Parameter vcinfo_408, VariableAccess target_30) {
		target_30.getTarget()=vcinfo_408
}

predicate func_31(Parameter vcinfo_408, VariableAccess target_31) {
		target_31.getTarget()=vcinfo_408
}

predicate func_32(Parameter vcinfo_408, VariableAccess target_32) {
		target_32.getTarget()=vcinfo_408
}

predicate func_33(Parameter vcinfo_408, VariableAccess target_33) {
		target_33.getTarget()=vcinfo_408
}

predicate func_34(Parameter vcinfo_408, VariableAccess target_34) {
		target_34.getTarget()=vcinfo_408
}

predicate func_35(PointerFieldAccess target_23, Function func, DeclStmt target_35) {
		target_35.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_23
		and target_35.getEnclosingFunction() = func
}

predicate func_36(Variable vupsample_476, ExprStmt target_37, AssignExpr target_36) {
		target_36.getLValue().(PointerFieldAccess).getTarget().getName()="spare_full"
		and target_36.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vupsample_476
		and target_36.getRValue().(Literal).getValue()="0"
		and target_36.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_37.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_37(Variable vupsample_476, PointerFieldAccess target_23, ExprStmt target_37) {
		target_37.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="rows_to_go"
		and target_37.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vupsample_476
		and target_37.getExpr().(AssignExpr).getRValue() instanceof SubExpr
		and target_37.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_23
}

predicate func_38(PointerFieldAccess target_25, Function func, DeclStmt target_38) {
		target_38.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_25
		and target_38.getEnclosingFunction() = func
}

predicate func_39(Variable vupsample_497, PointerFieldAccess target_25, ExprStmt target_39) {
		target_39.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="spare_full"
		and target_39.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vupsample_497
		and target_39.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_39.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_25
}

predicate func_40(Variable vupsample_497, PointerFieldAccess target_25, ExprStmt target_39, ExprStmt target_40) {
		target_40.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="rows_to_go"
		and target_40.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vupsample_497
		and target_40.getExpr().(AssignExpr).getRValue() instanceof SubExpr
		and target_40.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_25
		and target_39.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_40.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_41(PointerFieldAccess target_25, Function func, DeclStmt target_41) {
		target_41.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_25
		and target_41.getEnclosingFunction() = func
}

predicate func_42(PointerFieldAccess target_26, Function func, DeclStmt target_42) {
		target_42.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_26
		and target_42.getEnclosingFunction() = func
}

predicate func_43(Variable vupsample_541, PointerFieldAccess target_26, ExprStmt target_43) {
		target_43.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="rows_to_go"
		and target_43.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vupsample_541
		and target_43.getExpr().(AssignExpr).getRValue() instanceof SubExpr
		and target_43.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_26
}

predicate func_44(PointerFieldAccess target_26, Function func, DeclStmt target_44) {
		target_44.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_26
		and target_44.getEnclosingFunction() = func
}

predicate func_45(PointerFieldAccess target_28, Function func, DeclStmt target_45) {
		target_45.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_28
		and target_45.getEnclosingFunction() = func
}

predicate func_46(Parameter vcinfo_408, Variable vupsample_589, PointerFieldAccess target_28, ExprStmt target_46) {
		target_46.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="rows_to_go"
		and target_46.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vupsample_589
		and target_46.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="output_height"
		and target_46.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_408
		and target_46.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="output_scanline"
		and target_46.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_408
		and target_46.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_28
}

predicate func_47(PointerFieldAccess target_28, Function func, DeclStmt target_47) {
		target_47.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_28
		and target_47.getEnclosingFunction() = func
}

predicate func_48(Variable vmain_ptr_410, Variable vlines_per_iMCU_row_415, Variable vlines_left_in_iMCU_row_415, Parameter vnum_lines_408, Parameter vcinfo_408, BlockStmt target_48) {
		target_48.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vnum_lines_408
		and target_48.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vlines_left_in_iMCU_row_415
		and target_48.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_48.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlines_left_in_iMCU_row_415
		and target_48.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1"
		and target_48.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="buffer_full"
		and target_48.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmain_ptr_410
		and target_48.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vlines_per_iMCU_row_415
		and target_48.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_48.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("read_and_discard_scanlines")
		and target_48.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcinfo_408
		and target_48.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vnum_lines_408
		and target_48.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(VariableAccess).getTarget()=vnum_lines_408
}

predicate func_49(Variable vlines_to_read_416, Parameter vcinfo_408, ExprStmt target_49) {
		target_49.getExpr().(FunctionCall).getTarget().hasName("increment_simple_rowgroup_ctr")
		and target_49.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcinfo_408
		and target_49.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vlines_to_read_416
}

predicate func_50(Parameter vnum_lines_408, Parameter vcinfo_408, BlockStmt target_50) {
		target_50.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("increment_simple_rowgroup_ctr")
		and target_50.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcinfo_408
		and target_50.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vnum_lines_408
		and target_50.getStmt(1).(ReturnStmt).getExpr().(VariableAccess).getTarget()=vnum_lines_408
}

predicate func_51(Variable vmaster_412, IfStmt target_51) {
		target_51.getCondition().(PointerFieldAccess).getTarget().getName()="using_merged_upsample"
		and target_51.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmaster_412
		and target_51.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_51.getThen().(BlockStmt).getStmt(2) instanceof ExprStmt
		and target_51.getElse() instanceof BlockStmt
}

predicate func_52(Variable vmaster_412, BlockStmt target_52) {
		target_52.getStmt(0) instanceof IfStmt
		and target_52.getStmt(1).(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="using_merged_upsample"
		and target_52.getStmt(1).(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmaster_412
		and target_52.getStmt(1).(IfStmt).getThen() instanceof BlockStmt
		and target_52.getStmt(1).(IfStmt).getElse() instanceof BlockStmt
}

predicate func_53(Variable vmaster_412, IfStmt target_53) {
		target_53.getCondition().(PointerFieldAccess).getTarget().getName()="using_merged_upsample"
		and target_53.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmaster_412
		and target_53.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr() instanceof AssignExpr
		and target_53.getThen().(BlockStmt).getStmt(2) instanceof ExprStmt
		and target_53.getElse().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_53.getElse().(BlockStmt).getStmt(2) instanceof ExprStmt
}

predicate func_54(Variable vmaster_412, IfStmt target_54) {
		target_54.getCondition().(PointerFieldAccess).getTarget().getName()="using_merged_upsample"
		and target_54.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmaster_412
		and target_54.getThen() instanceof BlockStmt
		and target_54.getElse() instanceof BlockStmt
}

predicate func_55(BlockStmt target_55) {
		target_55.getStmt(1) instanceof ExprStmt
}

predicate func_56(Variable vmaster_412, IfStmt target_56) {
		target_56.getCondition().(PointerFieldAccess).getTarget().getName()="using_merged_upsample"
		and target_56.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmaster_412
		and target_56.getThen() instanceof BlockStmt
		and target_56.getElse() instanceof BlockStmt
}

predicate func_57(BlockStmt target_57) {
		target_57.getStmt(1).(ExprStmt).getExpr() instanceof AssignExpr
		and target_57.getStmt(2) instanceof ExprStmt
}

predicate func_58(BlockStmt target_58) {
		target_58.getStmt(1) instanceof ExprStmt
		and target_58.getStmt(2) instanceof ExprStmt
}

predicate func_59(BlockStmt target_59) {
		target_59.getStmt(1) instanceof ExprStmt
}

from Function func, Variable vmain_ptr_410, Variable vmaster_412, Variable vlines_per_iMCU_row_415, Variable vlines_left_in_iMCU_row_415, Variable vlines_to_skip_416, Variable vlines_to_read_416, Variable vupsample_476, Variable vupsample_481, Variable vupsample_497, Variable vupsample_502, Parameter vnum_lines_408, Parameter vcinfo_408, Variable vupsample_541, Variable vupsample_545, Variable vupsample_589, Variable vupsample_592, PointerFieldAccess target_6, PointerFieldAccess target_7, SubExpr target_8, ExprStmt target_9, ExprStmt target_10, RelationalOperation target_11, ExprStmt target_12, ExprStmt target_13, ExprStmt target_14, SubExpr target_15, ExprStmt target_16, ExprStmt target_17, PointerFieldAccess target_18, IfStmt target_19, SubExpr target_20, ReturnStmt target_22, PointerFieldAccess target_23, DeclStmt target_24, PointerFieldAccess target_25, PointerFieldAccess target_26, ExprStmt target_27, PointerFieldAccess target_28, ExprStmt target_29, VariableAccess target_30, VariableAccess target_31, VariableAccess target_32, VariableAccess target_33, VariableAccess target_34, DeclStmt target_35, AssignExpr target_36, ExprStmt target_37, DeclStmt target_38, ExprStmt target_39, ExprStmt target_40, DeclStmt target_41, DeclStmt target_42, ExprStmt target_43, DeclStmt target_44, DeclStmt target_45, ExprStmt target_46, DeclStmt target_47, BlockStmt target_48, ExprStmt target_49, BlockStmt target_50, IfStmt target_51, BlockStmt target_52, IfStmt target_53, IfStmt target_54, BlockStmt target_55, IfStmt target_56, BlockStmt target_57, BlockStmt target_58, BlockStmt target_59
where
not func_0(vcinfo_408, target_48, target_12, target_16)
and not func_1(vcinfo_408, target_49, target_46)
and not func_2(vmaster_412, target_50, target_51)
and not func_3(vmaster_412, target_52, target_53, target_54)
and not func_4(vmaster_412, target_55, target_51, target_56)
and not func_5(vmaster_412, target_54, func)
and func_6(vcinfo_408, target_48, target_6)
and func_7(vcinfo_408, target_7)
and func_8(vupsample_476, vcinfo_408, target_8)
and func_9(vupsample_481, vcinfo_408, target_23, target_9)
and func_10(vupsample_481, vcinfo_408, target_23, target_10)
and func_11(vlines_left_in_iMCU_row_415, vnum_lines_408, target_50, target_11)
and func_12(vlines_left_in_iMCU_row_415, vcinfo_408, target_11, target_12)
and func_13(vmain_ptr_410, target_11, target_13)
and func_14(vmain_ptr_410, target_11, target_14)
and func_15(vupsample_497, vcinfo_408, target_15)
and func_16(vupsample_502, vcinfo_408, target_25, target_16)
and func_17(vupsample_502, vcinfo_408, target_25, target_17)
and func_18(vcinfo_408, target_52, target_18)
and func_19(vmain_ptr_410, vlines_per_iMCU_row_415, vlines_to_skip_416, vlines_to_read_416, vcinfo_408, target_18, target_19)
and func_20(vcinfo_408, vupsample_541, target_20)
and func_22(vnum_lines_408, target_18, target_22)
and func_23(vmaster_412, target_57, target_23)
and func_24(target_23, func, target_24)
and func_25(vmaster_412, target_58, target_25)
and func_26(vmaster_412, target_55, target_26)
and func_27(vcinfo_408, vupsample_545, target_26, target_27)
and func_28(vmaster_412, target_59, target_28)
and func_29(vcinfo_408, vupsample_592, target_28, target_29)
and func_30(vcinfo_408, target_30)
and func_31(vcinfo_408, target_31)
and func_32(vcinfo_408, target_32)
and func_33(vcinfo_408, target_33)
and func_34(vcinfo_408, target_34)
and func_35(target_23, func, target_35)
and func_36(vupsample_476, target_37, target_36)
and func_37(vupsample_476, target_23, target_37)
and func_38(target_25, func, target_38)
and func_39(vupsample_497, target_25, target_39)
and func_40(vupsample_497, target_25, target_39, target_40)
and func_41(target_25, func, target_41)
and func_42(target_26, func, target_42)
and func_43(vupsample_541, target_26, target_43)
and func_44(target_26, func, target_44)
and func_45(target_28, func, target_45)
and func_46(vcinfo_408, vupsample_589, target_28, target_46)
and func_47(target_28, func, target_47)
and func_48(vmain_ptr_410, vlines_per_iMCU_row_415, vlines_left_in_iMCU_row_415, vnum_lines_408, vcinfo_408, target_48)
and func_49(vlines_to_read_416, vcinfo_408, target_49)
and func_50(vnum_lines_408, vcinfo_408, target_50)
and func_51(vmaster_412, target_51)
and func_52(vmaster_412, target_52)
and func_53(vmaster_412, target_53)
and func_54(vmaster_412, target_54)
and func_55(target_55)
and func_56(vmaster_412, target_56)
and func_57(target_57)
and func_58(target_58)
and func_59(target_59)
and vmain_ptr_410.getType().hasName("my_main_ptr")
and vmaster_412.getType().hasName("my_master_ptr")
and vlines_per_iMCU_row_415.getType().hasName("JDIMENSION")
and vlines_left_in_iMCU_row_415.getType().hasName("JDIMENSION")
and vlines_to_skip_416.getType().hasName("JDIMENSION")
and vlines_to_read_416.getType().hasName("JDIMENSION")
and vupsample_476.getType().hasName("my_merged_upsample_ptr")
and vupsample_481.getType().hasName("my_upsample_ptr")
and vupsample_497.getType().hasName("my_merged_upsample_ptr")
and vupsample_502.getType().hasName("my_upsample_ptr")
and vnum_lines_408.getType().hasName("JDIMENSION")
and vcinfo_408.getType().hasName("j_decompress_ptr")
and vupsample_541.getType().hasName("my_merged_upsample_ptr")
and vupsample_545.getType().hasName("my_upsample_ptr")
and vupsample_589.getType().hasName("my_merged_upsample_ptr")
and vupsample_592.getType().hasName("my_upsample_ptr")
and vmain_ptr_410.getParentScope+() = func
and vmaster_412.getParentScope+() = func
and vlines_per_iMCU_row_415.getParentScope+() = func
and vlines_left_in_iMCU_row_415.getParentScope+() = func
and vlines_to_skip_416.getParentScope+() = func
and vlines_to_read_416.getParentScope+() = func
and vupsample_476.getParentScope+() = func
and vupsample_481.getParentScope+() = func
and vupsample_497.getParentScope+() = func
and vupsample_502.getParentScope+() = func
and vnum_lines_408.getParentScope+() = func
and vcinfo_408.getParentScope+() = func
and vupsample_541.getParentScope+() = func
and vupsample_545.getParentScope+() = func
and vupsample_589.getParentScope+() = func
and vupsample_592.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
