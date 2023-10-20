/**
 * @name ffmpeg-ce7aee9b733134649a6ce2fa743e51733f33e67e-dpcm_decode_frame
 * @id cpp/ffmpeg/ce7aee9b733134649a6ce2fa743e51733f33e67e/dpcm-decode-frame
 * @description ffmpeg-ce7aee9b733134649a6ce2fa743e51733f33e67e-libavcodec/dpcm.c-dpcm_decode_frame CVE-2011-3951
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vbuf_size_177, Variable vbuf_end_178, Variable vstereo_183, ExprStmt target_3, ExprStmt target_4, RelationalOperation target_5, IfStmt target_6, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vstereo_183
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vbuf_size_177
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="1"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vbuf_size_177
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vbuf_end_178
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_0)
		and target_3.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_5.getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_6.getCondition().(VariableAccess).getLocation()))
}

predicate func_2(Variable vbuf_size_177, VariableAccess target_2) {
		target_2.getTarget()=vbuf_size_177
}

predicate func_3(Variable vbuf_size_177, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_3.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vbuf_size_177
}

predicate func_4(Variable vbuf_size_177, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_4.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vbuf_size_177
		and target_4.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="8"
}

predicate func_5(Variable vbuf_end_178, RelationalOperation target_5) {
		 (target_5 instanceof GTExpr or target_5 instanceof LTExpr)
		and target_5.getLesserOperand().(VariableAccess).getTarget().getType().hasName("const uint8_t *")
		and target_5.getGreaterOperand().(VariableAccess).getTarget()=vbuf_end_178
}

predicate func_6(Variable vstereo_183, IfStmt target_6) {
		target_6.getCondition().(VariableAccess).getTarget()=vstereo_183
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("int[2]")
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(FunctionCall).getTarget().hasName("bytestream_get_byte")
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_6.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("int[2]")
		and target_6.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_6.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(FunctionCall).getTarget().hasName("bytestream_get_byte")
		and target_6.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_6.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("int[2]")
		and target_6.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_6.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("bytestream_get_le16")
		and target_6.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("const uint8_t *")
}

from Function func, Parameter vavpkt_174, Variable vbuf_size_177, Variable vbuf_end_178, Variable vstereo_183, VariableAccess target_2, ExprStmt target_3, ExprStmt target_4, RelationalOperation target_5, IfStmt target_6
where
not func_0(vbuf_size_177, vbuf_end_178, vstereo_183, target_3, target_4, target_5, target_6, func)
and func_2(vbuf_size_177, target_2)
and func_3(vbuf_size_177, target_3)
and func_4(vbuf_size_177, target_4)
and func_5(vbuf_end_178, target_5)
and func_6(vstereo_183, target_6)
and vavpkt_174.getType().hasName("AVPacket *")
and vbuf_size_177.getType().hasName("int")
and vbuf_end_178.getType().hasName("const uint8_t *")
and vstereo_183.getType().hasName("int")
and vavpkt_174.getFunction() = func
and vbuf_size_177.(LocalVariable).getFunction() = func
and vbuf_end_178.(LocalVariable).getFunction() = func
and vstereo_183.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
