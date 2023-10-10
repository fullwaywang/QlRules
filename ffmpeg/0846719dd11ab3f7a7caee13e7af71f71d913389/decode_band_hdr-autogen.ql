/**
 * @name ffmpeg-0846719dd11ab3f7a7caee13e7af71f71d913389-decode_band_hdr
 * @id cpp/ffmpeg/0846719dd11ab3f7a7caee13e7af71f71d913389/decode-band-hdr
 * @description ffmpeg-0846719dd11ab3f7a7caee13e7af71f71d913389-libavcodec/indeo4.c-decode_band_hdr CVE-2012-2791
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vband_325, Parameter vavctx_326, Variable vtransform_id_328, LogicalOrExpr target_2, ExprStmt target_3, ExprStmt target_4, ExprStmt target_5, ExprStmt target_6, LogicalOrExpr target_7, ArrayExpr target_8) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vtransform_id_328
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="10"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="blk_size"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vband_325
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="8"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_326
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="wrong transform size!\n"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="3199971767"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_7.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_8.getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vband_325, Variable vtransform_id_328, LogicalOrExpr target_2, ExprStmt target_9, EqualityOperation target_10, ArrayExpr target_11) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="transform_size"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vband_325
		and target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vtransform_id_328
		and target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="10"
		and target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(Literal).getValue()="8"
		and target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="4"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(7)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_10.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_11.getArrayOffset().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_2(LogicalOrExpr target_2) {
		target_2.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("get_bits1")
		and target_2.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="gb"
		and target_2.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("IVI4DecContext *")
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="frame_type"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("IVI4DecContext *")
}

predicate func_3(Parameter vband_325, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="glob_quant"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vband_325
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("get_bits")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="gb"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("IVI4DecContext *")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="5"
}

predicate func_4(Parameter vband_325, Variable vtransform_id_328, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="inv_transform"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vband_325
		and target_4.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="inv_trans"
		and target_4.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType() instanceof ArrayType
		and target_4.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vtransform_id_328
}

predicate func_5(Parameter vavctx_326, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("av_log_ask_for_sample")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_326
		and target_5.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="DCT transform not supported yet!\n"
}

predicate func_6(Parameter vavctx_326, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_326
		and target_6.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_6.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="mismatching scan table!\n"
}

predicate func_7(Variable vtransform_id_328, LogicalOrExpr target_7) {
		target_7.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vtransform_id_328
		and target_7.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="7"
		and target_7.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vtransform_id_328
		and target_7.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="9"
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtransform_id_328
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="17"
}

predicate func_8(Variable vtransform_id_328, ArrayExpr target_8) {
		target_8.getArrayBase().(VariableAccess).getTarget().getType() instanceof ArrayType
		and target_8.getArrayOffset().(VariableAccess).getTarget()=vtransform_id_328
}

predicate func_9(Parameter vband_325, Variable vtransform_id_328, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="is_2d_trans"
		and target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vband_325
		and target_9.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="is_2d_trans"
		and target_9.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType() instanceof ArrayType
		and target_9.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vtransform_id_328
}

predicate func_10(Parameter vband_325, EqualityOperation target_10) {
		target_10.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_10.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="4"
		and target_10.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_10.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="10"
		and target_10.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="blk_size"
		and target_10.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vband_325
		and target_10.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="4"
}

predicate func_11(Variable vtransform_id_328, ArrayExpr target_11) {
		target_11.getArrayBase().(VariableAccess).getTarget().getType() instanceof ArrayType
		and target_11.getArrayOffset().(VariableAccess).getTarget()=vtransform_id_328
}

from Function func, Parameter vband_325, Parameter vavctx_326, Variable vtransform_id_328, LogicalOrExpr target_2, ExprStmt target_3, ExprStmt target_4, ExprStmt target_5, ExprStmt target_6, LogicalOrExpr target_7, ArrayExpr target_8, ExprStmt target_9, EqualityOperation target_10, ArrayExpr target_11
where
not func_0(vband_325, vavctx_326, vtransform_id_328, target_2, target_3, target_4, target_5, target_6, target_7, target_8)
and not func_1(vband_325, vtransform_id_328, target_2, target_9, target_10, target_11)
and func_2(target_2)
and func_3(vband_325, target_3)
and func_4(vband_325, vtransform_id_328, target_4)
and func_5(vavctx_326, target_5)
and func_6(vavctx_326, target_6)
and func_7(vtransform_id_328, target_7)
and func_8(vtransform_id_328, target_8)
and func_9(vband_325, vtransform_id_328, target_9)
and func_10(vband_325, target_10)
and func_11(vtransform_id_328, target_11)
and vband_325.getType().hasName("IVIBandDesc *")
and vavctx_326.getType().hasName("AVCodecContext *")
and vtransform_id_328.getType().hasName("int")
and vband_325.getFunction() = func
and vavctx_326.getFunction() = func
and vtransform_id_328.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
