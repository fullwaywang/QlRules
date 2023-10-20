/**
 * @name ffmpeg-c0d68be555f5858703383040e04fcd6529777061-parse_picture_segment
 * @id cpp/ffmpeg/c0d68be555f5858703383040e04fcd6529777061/parse-picture-segment
 * @description ffmpeg-c0d68be555f5858703383040e04fcd6529777061-libavcodec/pgssubdec.c-parse_picture_segment CVE-2013-0852
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vbuf_size_176, Variable vrle_bitmap_len_181, Parameter vavctx_175, ExprStmt target_1, ExprStmt target_2, ExprStmt target_3, ExprStmt target_4, ExprStmt target_5, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vbuf_size_176
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vrle_bitmap_len_181
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_175
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="too much RLE data\n"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1094995529"
		and (func.getEntryPoint().(BlockStmt).getStmt(16)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(16).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vbuf_size_176, ExprStmt target_1) {
		target_1.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vbuf_size_176
		and target_1.getExpr().(AssignSubExpr).getRValue().(Literal).getValue()="7"
}

predicate func_2(Parameter vbuf_size_176, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_2.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="rle"
		and target_2.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="pictures"
		and target_2.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("PGSSubContext *")
		and target_2.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("uint16_t")
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("const uint8_t *")
		and target_2.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vbuf_size_176
}

predicate func_3(Variable vrle_bitmap_len_181, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrle_bitmap_len_181
		and target_3.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(FunctionCall).getTarget().hasName("bytestream_get_be24")
		and target_3.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("const uint8_t *")
		and target_3.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(MulExpr).getValue()="4"
}

predicate func_4(Variable vrle_bitmap_len_181, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("av_fast_malloc")
		and target_4.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="rle"
		and target_4.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="pictures"
		and target_4.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("PGSSubContext *")
		and target_4.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("uint16_t")
		and target_4.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="rle_buffer_size"
		and target_4.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="pictures"
		and target_4.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("PGSSubContext *")
		and target_4.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("uint16_t")
		and target_4.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vrle_bitmap_len_181
}

predicate func_5(Parameter vavctx_175, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_175
		and target_5.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_5.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Bitmap dimensions larger than video.\n"
}

from Function func, Parameter vbuf_size_176, Variable vrle_bitmap_len_181, Parameter vavctx_175, ExprStmt target_1, ExprStmt target_2, ExprStmt target_3, ExprStmt target_4, ExprStmt target_5
where
not func_0(vbuf_size_176, vrle_bitmap_len_181, vavctx_175, target_1, target_2, target_3, target_4, target_5, func)
and func_1(vbuf_size_176, target_1)
and func_2(vbuf_size_176, target_2)
and func_3(vrle_bitmap_len_181, target_3)
and func_4(vrle_bitmap_len_181, target_4)
and func_5(vavctx_175, target_5)
and vbuf_size_176.getType().hasName("int")
and vrle_bitmap_len_181.getType().hasName("unsigned int")
and vavctx_175.getType().hasName("AVCodecContext *")
and vbuf_size_176.getFunction() = func
and vrle_bitmap_len_181.(LocalVariable).getFunction() = func
and vavctx_175.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
