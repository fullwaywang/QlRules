/**
 * @name ffmpeg-fddef964e8aa4a2c123e470db1436a082ff6bcf3-filter_frame
 * @id cpp/ffmpeg/fddef964e8aa4a2c123e470db1436a082ff6bcf3/filter-frame
 * @description ffmpeg-fddef964e8aa4a2c123e470db1436a082ff6bcf3-libavfilter/vf_colorspace.c-filter_frame CVE-2020-22048
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vout_770, RelationalOperation target_10, ExprStmt target_11, ExprStmt target_12) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("av_frame_free")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vout_770
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation())
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation().isBefore(target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vin_762, LogicalOrExpr target_13, MulExpr target_14, ExprStmt target_15) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("av_frame_free")
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vin_762
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
		and target_14.getRightOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation())
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation().isBefore(target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_2(Variable vout_770, LogicalOrExpr target_13, FunctionCall target_16, ExprStmt target_15) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("av_frame_free")
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vout_770
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
		and target_16.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation())
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation().isBefore(target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_3(Parameter vin_762, PointerFieldAccess target_17, FunctionCall target_18, ExprStmt target_7) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(FunctionCall).getTarget().hasName("av_frame_free")
		and target_3.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vin_762
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_17
		and target_18.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation())
		and target_3.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_4(Variable vout_770, PointerFieldAccess target_17, FunctionCall target_19, ExprStmt target_7) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(FunctionCall).getTarget().hasName("av_frame_free")
		and target_4.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vout_770
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_4
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_17
		and target_19.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation())
		and target_4.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_5(Parameter vin_762, RelationalOperation target_20, ExprStmt target_7, ConditionalExpr target_21) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(FunctionCall).getTarget().hasName("av_frame_free")
		and target_5.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vin_762
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_5
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_20
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_5.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation())
		and target_5.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation().isBefore(target_21.getCondition().(RelationalOperation).getGreaterOperand().(BinaryBitwiseOperation).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_6(Variable vout_770, RelationalOperation target_20, ExprStmt target_7, FunctionCall target_22) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(FunctionCall).getTarget().hasName("av_frame_free")
		and target_6.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vout_770
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_6
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_20
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_6.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation())
		and target_6.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation().isBefore(target_22.getArgument(1).(VariableAccess).getLocation()))
}

predicate func_7(Variable vout_770, Variable vres_771, Parameter vin_762, PointerFieldAccess target_17, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vres_771
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_frame_copy")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vout_770
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vin_762
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_17
}

predicate func_8(Variable vres_771, RelationalOperation target_23, ReturnStmt target_8) {
		target_8.getExpr().(VariableAccess).getTarget()=vres_771
		and target_8.getParent().(IfStmt).getCondition()=target_23
}

predicate func_9(Variable vres_771, RelationalOperation target_20, ReturnStmt target_9) {
		target_9.getExpr().(VariableAccess).getTarget()=vres_771
		and target_9.getParent().(IfStmt).getCondition()=target_20
}

predicate func_10(Variable vres_771, RelationalOperation target_10) {
		 (target_10 instanceof GTExpr or target_10 instanceof LTExpr)
		and target_10.getLesserOperand().(VariableAccess).getTarget()=vres_771
		and target_10.getGreaterOperand().(Literal).getValue()="0"
}

predicate func_11(Variable vout_770, Variable vres_771, Parameter vin_762, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vres_771
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_frame_copy_props")
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vout_770
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vin_762
}

predicate func_12(Variable vout_770, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="color_primaries"
		and target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vout_770
		and target_12.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="user_prm"
		and target_12.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(ArrayExpr).getArrayOffset().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="user_all"
		and target_12.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(ArrayExpr).getArrayOffset().(ConditionalExpr).getElse().(PointerFieldAccess).getTarget().getName()="user_all"
		and target_12.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(PointerFieldAccess).getTarget().getName()="user_prm"
}

predicate func_13(LogicalOrExpr target_13) {
		target_13.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_13.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="dither_scratch_base"
		and target_13.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_13.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_13.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="dither_scratch_base"
		and target_13.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_13.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_13.getAnOperand().(NotExpr).getOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="dither_scratch_base"
		and target_13.getAnOperand().(NotExpr).getOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_13.getAnOperand().(NotExpr).getOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
}

predicate func_14(Parameter vin_762, MulExpr target_14) {
		target_14.getLeftOperand().(SizeofExprOperator).getValue()="4"
		and target_14.getRightOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_14.getRightOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vin_762
		and target_14.getRightOperand().(AddExpr).getAnOperand().(Literal).getValue()="4"
}

predicate func_15(Variable vout_770, Variable vres_771, Parameter vin_762, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vres_771
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("create_filtergraph")
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vin_762
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vout_770
}

predicate func_16(Variable vout_770, FunctionCall target_16) {
		target_16.getTarget().hasName("av_pix_fmt_desc_get")
		and target_16.getArgument(0).(PointerFieldAccess).getTarget().getName()="format"
		and target_16.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vout_770
}

predicate func_17(PointerFieldAccess target_17) {
		target_17.getTarget().getName()="yuv2yuv_passthrough"
}

predicate func_18(Parameter vin_762, FunctionCall target_18) {
		target_18.getTarget().hasName("av_pix_fmt_desc_get")
		and target_18.getArgument(0).(PointerFieldAccess).getTarget().getName()="format"
		and target_18.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vin_762
}

predicate func_19(Variable vout_770, FunctionCall target_19) {
		target_19.getTarget().hasName("av_pix_fmt_desc_get")
		and target_19.getArgument(0).(PointerFieldAccess).getTarget().getName()="format"
		and target_19.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vout_770
}

predicate func_20(Variable vres_771, RelationalOperation target_20) {
		 (target_20 instanceof GTExpr or target_20 instanceof LTExpr)
		and target_20.getLesserOperand().(VariableAccess).getTarget()=vres_771
		and target_20.getGreaterOperand().(Literal).getValue()="0"
}

predicate func_21(Parameter vin_762, ConditionalExpr target_21) {
		target_21.getCondition().(RelationalOperation).getGreaterOperand().(BinaryBitwiseOperation).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_21.getCondition().(RelationalOperation).getGreaterOperand().(BinaryBitwiseOperation).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vin_762
		and target_21.getCondition().(RelationalOperation).getGreaterOperand().(BinaryBitwiseOperation).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_21.getCondition().(RelationalOperation).getGreaterOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="1"
		and target_21.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("ff_filter_get_nb_threads")
		and target_21.getThen().(FunctionCall).getTarget().hasName("ff_filter_get_nb_threads")
		and target_21.getElse().(BinaryBitwiseOperation).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_21.getElse().(BinaryBitwiseOperation).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vin_762
		and target_21.getElse().(BinaryBitwiseOperation).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_21.getElse().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="1"
}

predicate func_22(Variable vout_770, FunctionCall target_22) {
		target_22.getTarget().hasName("ff_filter_frame")
		and target_22.getArgument(1).(VariableAccess).getTarget()=vout_770
}

predicate func_23(Variable vres_771, RelationalOperation target_23) {
		 (target_23 instanceof GTExpr or target_23 instanceof LTExpr)
		and target_23.getLesserOperand().(VariableAccess).getTarget()=vres_771
		and target_23.getGreaterOperand().(Literal).getValue()="0"
}

from Function func, Variable vout_770, Variable vres_771, Parameter vin_762, ExprStmt target_7, ReturnStmt target_8, ReturnStmt target_9, RelationalOperation target_10, ExprStmt target_11, ExprStmt target_12, LogicalOrExpr target_13, MulExpr target_14, ExprStmt target_15, FunctionCall target_16, PointerFieldAccess target_17, FunctionCall target_18, FunctionCall target_19, RelationalOperation target_20, ConditionalExpr target_21, FunctionCall target_22, RelationalOperation target_23
where
not func_0(vout_770, target_10, target_11, target_12)
and not func_1(vin_762, target_13, target_14, target_15)
and not func_2(vout_770, target_13, target_16, target_15)
and not func_3(vin_762, target_17, target_18, target_7)
and not func_4(vout_770, target_17, target_19, target_7)
and not func_5(vin_762, target_20, target_7, target_21)
and not func_6(vout_770, target_20, target_7, target_22)
and func_7(vout_770, vres_771, vin_762, target_17, target_7)
and func_8(vres_771, target_23, target_8)
and func_9(vres_771, target_20, target_9)
and func_10(vres_771, target_10)
and func_11(vout_770, vres_771, vin_762, target_11)
and func_12(vout_770, target_12)
and func_13(target_13)
and func_14(vin_762, target_14)
and func_15(vout_770, vres_771, vin_762, target_15)
and func_16(vout_770, target_16)
and func_17(target_17)
and func_18(vin_762, target_18)
and func_19(vout_770, target_19)
and func_20(vres_771, target_20)
and func_21(vin_762, target_21)
and func_22(vout_770, target_22)
and func_23(vres_771, target_23)
and vout_770.getType().hasName("AVFrame *")
and vres_771.getType().hasName("int")
and vin_762.getType().hasName("AVFrame *")
and vout_770.getParentScope+() = func
and vres_771.getParentScope+() = func
and vin_762.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
