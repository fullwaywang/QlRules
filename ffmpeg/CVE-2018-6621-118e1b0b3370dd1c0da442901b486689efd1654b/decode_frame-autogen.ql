/**
 * @name ffmpeg-118e1b0b3370dd1c0da442901b486689efd1654b-decode_frame
 * @id cpp/ffmpeg/118e1b0b3370dd1c0da442901b486689efd1654b/decode-frame
 * @description ffmpeg-118e1b0b3370dd1c0da442901b486689efd1654b-libavcodec/utvideodec.c-decode_frame CVE-2018-6621
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vavctx_592, Variable vc_597, Variable vj_598, Variable vmax_slice_size_600, Variable vslice_start_600, Variable vslice_end_600, Variable vslice_size_600, Variable vgb_602, ExprStmt target_2, ExprStmt target_3, RelationalOperation target_4, RelationalOperation target_5, ExprStmt target_6, ExprStmt target_7, LogicalOrExpr target_8, ExprStmt target_9, AddressOfExpr target_10) {
	exists(ForStmt target_0 |
		target_0.getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vj_598
		and target_0.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vj_598
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="slices"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_597
		and target_0.getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vj_598
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vslice_end_600
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("bytestream2_get_le32u")
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vgb_602
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vslice_end_600
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vslice_end_600
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vslice_start_600
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("bytestream2_get_bytes_left")
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vslice_end_600
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(Literal).getValue()="1024"
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_592
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Incorrect slice size\n"
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1094995529"
		and target_0.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vslice_size_600
		and target_0.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vslice_end_600
		and target_0.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vslice_start_600
		and target_0.getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vslice_start_600
		and target_0.getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vslice_end_600
		and target_0.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmax_slice_size_600
		and target_0.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vmax_slice_size_600
		and target_0.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vslice_size_600
		and target_0.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(VariableAccess).getTarget()=vmax_slice_size_600
		and target_0.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(VariableAccess).getTarget()=vslice_size_600
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_4.getGreaterOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_6.getExpr().(AssignPointerAddExpr).getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_0.getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_10.getOperand().(VariableAccess).getLocation().isBefore(target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vavctx_592, Variable vc_597, Variable vj_598, Variable vmax_slice_size_600, Variable vslice_start_600, Variable vslice_end_600, Variable vslice_size_600, Variable vgb_602, ForStmt target_1) {
		target_1.getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vj_598
		and target_1.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vj_598
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="slices"
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_597
		and target_1.getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vj_598
		and target_1.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vslice_end_600
		and target_1.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("bytestream2_get_le32u")
		and target_1.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vgb_602
		and target_1.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vslice_end_600
		and target_1.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_1.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vslice_end_600
		and target_1.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vslice_start_600
		and target_1.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("bytestream2_get_bytes_left")
		and target_1.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vslice_end_600
		and target_1.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_1.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_592
		and target_1.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_1.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Incorrect slice size\n"
		and target_1.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1094995529"
		and target_1.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vslice_size_600
		and target_1.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vslice_end_600
		and target_1.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vslice_start_600
		and target_1.getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vslice_start_600
		and target_1.getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vslice_end_600
		and target_1.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmax_slice_size_600
		and target_1.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vmax_slice_size_600
		and target_1.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vslice_size_600
		and target_1.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(VariableAccess).getTarget()=vmax_slice_size_600
		and target_1.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(VariableAccess).getTarget()=vslice_size_600
}

predicate func_2(Parameter vavctx_592, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_592
		and target_2.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_2.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Insufficient data for a plane\n"
}

predicate func_3(Parameter vavctx_592, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_592
		and target_3.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_3.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Incorrect slice size\n"
}

predicate func_4(Variable vc_597, Variable vgb_602, RelationalOperation target_4) {
		 (target_4 instanceof GTExpr or target_4 instanceof LTExpr)
		and target_4.getLesserOperand().(FunctionCall).getTarget().hasName("bytestream2_get_bytes_left")
		and target_4.getLesserOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vgb_602
		and target_4.getGreaterOperand().(AddExpr).getAnOperand().(Literal).getValue()="1024"
		and target_4.getGreaterOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(Literal).getValue()="4"
		and target_4.getGreaterOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="slices"
		and target_4.getGreaterOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_597
}

predicate func_5(Variable vc_597, Variable vj_598, RelationalOperation target_5) {
		 (target_5 instanceof GTExpr or target_5 instanceof LTExpr)
		and target_5.getLesserOperand().(VariableAccess).getTarget()=vj_598
		and target_5.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="slices"
		and target_5.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_597
}

predicate func_6(Variable vc_597, Variable vj_598, ExprStmt target_6) {
		target_6.getExpr().(AssignPointerAddExpr).getRValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="control_stream_size"
		and target_6.getExpr().(AssignPointerAddExpr).getRValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_597
		and target_6.getExpr().(AssignPointerAddExpr).getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vj_598
}

predicate func_7(Variable vslice_start_600, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vslice_start_600
		and target_7.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_8(Variable vslice_start_600, Variable vslice_end_600, Variable vgb_602, LogicalOrExpr target_8) {
		target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vslice_end_600
		and target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vslice_end_600
		and target_8.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vslice_start_600
		and target_8.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("bytestream2_get_bytes_left")
		and target_8.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vgb_602
		and target_8.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vslice_end_600
}

predicate func_9(Variable vslice_end_600, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vslice_end_600
		and target_9.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_10(Variable vgb_602, AddressOfExpr target_10) {
		target_10.getOperand().(VariableAccess).getTarget()=vgb_602
}

from Function func, Parameter vavctx_592, Variable vc_597, Variable vj_598, Variable vmax_slice_size_600, Variable vslice_start_600, Variable vslice_end_600, Variable vslice_size_600, Variable vgb_602, ForStmt target_1, ExprStmt target_2, ExprStmt target_3, RelationalOperation target_4, RelationalOperation target_5, ExprStmt target_6, ExprStmt target_7, LogicalOrExpr target_8, ExprStmt target_9, AddressOfExpr target_10
where
not func_0(vavctx_592, vc_597, vj_598, vmax_slice_size_600, vslice_start_600, vslice_end_600, vslice_size_600, vgb_602, target_2, target_3, target_4, target_5, target_6, target_7, target_8, target_9, target_10)
and func_1(vavctx_592, vc_597, vj_598, vmax_slice_size_600, vslice_start_600, vslice_end_600, vslice_size_600, vgb_602, target_1)
and func_2(vavctx_592, target_2)
and func_3(vavctx_592, target_3)
and func_4(vc_597, vgb_602, target_4)
and func_5(vc_597, vj_598, target_5)
and func_6(vc_597, vj_598, target_6)
and func_7(vslice_start_600, target_7)
and func_8(vslice_start_600, vslice_end_600, vgb_602, target_8)
and func_9(vslice_end_600, target_9)
and func_10(vgb_602, target_10)
and vavctx_592.getType().hasName("AVCodecContext *")
and vc_597.getType().hasName("UtvideoContext *")
and vj_598.getType().hasName("int")
and vmax_slice_size_600.getType().hasName("int")
and vslice_start_600.getType().hasName("int")
and vslice_end_600.getType().hasName("int")
and vslice_size_600.getType().hasName("int")
and vgb_602.getType().hasName("GetByteContext")
and vavctx_592.getParentScope+() = func
and vc_597.getParentScope+() = func
and vj_598.getParentScope+() = func
and vmax_slice_size_600.getParentScope+() = func
and vslice_start_600.getParentScope+() = func
and vslice_end_600.getParentScope+() = func
and vslice_size_600.getParentScope+() = func
and vgb_602.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
