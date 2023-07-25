/**
 * @name ffmpeg-3030fb7e0d41836f8add6399e9a7c7b740b48bfd-vmd_decode
 * @id cpp/ffmpeg/3030fb7e0d41836f8add6399e9a7c7b740b48bfd/vmd-decode
 * @description ffmpeg-3030fb7e0d41836f8add6399e9a7c7b740b48bfd-libavcodec/vmdvideo.c-vmd_decode CVE-2014-9603
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vgb_189, Variable vlen_194, Variable vofs_195, Variable vframe_width_198, EqualityOperation target_1, AddressOfExpr target_2, AddressOfExpr target_3, ExprStmt target_4, ExprStmt target_5, ExprStmt target_6, AddressOfExpr target_7, SubExpr target_8, LogicalOrExpr target_9) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vofs_195
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vlen_194
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vframe_width_198
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("bytestream2_get_bytes_left")
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vgb_189
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_194
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1094995529"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation().isBefore(target_3.getOperand().(VariableAccess).getLocation())
		and target_4.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_5.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_6.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_7.getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation())
		and target_8.getLeftOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_9.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vgb_189, EqualityOperation target_1) {
		target_1.getAnOperand().(FunctionCall).getTarget().hasName("bytestream2_peek_byte")
		and target_1.getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vgb_189
		and target_1.getAnOperand().(HexLiteral).getValue()="255"
}

predicate func_2(Variable vgb_189, AddressOfExpr target_2) {
		target_2.getOperand().(VariableAccess).getTarget()=vgb_189
}

predicate func_3(Variable vgb_189, AddressOfExpr target_3) {
		target_3.getOperand().(VariableAccess).getTarget()=vgb_189
}

predicate func_4(Variable vgb_189, Variable vlen_194, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("bytestream2_skip")
		and target_4.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vgb_189
		and target_4.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vlen_194
}

predicate func_5(Variable vgb_189, Variable vlen_194, Variable vofs_195, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("bytestream2_get_buffer")
		and target_5.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vgb_189
		and target_5.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_5.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vofs_195
		and target_5.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlen_194
}

predicate func_6(Variable vofs_195, ExprStmt target_6) {
		target_6.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vofs_195
		and target_6.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_7(Variable vofs_195, AddressOfExpr target_7) {
		target_7.getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_7.getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vofs_195
}

predicate func_8(Variable vofs_195, Variable vframe_width_198, SubExpr target_8) {
		target_8.getLeftOperand().(VariableAccess).getTarget()=vframe_width_198
		and target_8.getRightOperand().(VariableAccess).getTarget()=vofs_195
}

predicate func_9(Variable vlen_194, Variable vofs_195, Variable vframe_width_198, LogicalOrExpr target_9) {
		target_9.getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vofs_195
		and target_9.getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vlen_194
		and target_9.getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_9.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vframe_width_198
		and target_9.getAnOperand().(NotExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_9.getAnOperand().(NotExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="prev_frame"
		and target_9.getAnOperand().(NotExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("VmdVideoContext *")
		and target_9.getAnOperand().(NotExpr).getOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

from Function func, Variable vgb_189, Variable vlen_194, Variable vofs_195, Variable vframe_width_198, EqualityOperation target_1, AddressOfExpr target_2, AddressOfExpr target_3, ExprStmt target_4, ExprStmt target_5, ExprStmt target_6, AddressOfExpr target_7, SubExpr target_8, LogicalOrExpr target_9
where
not func_0(vgb_189, vlen_194, vofs_195, vframe_width_198, target_1, target_2, target_3, target_4, target_5, target_6, target_7, target_8, target_9)
and func_1(vgb_189, target_1)
and func_2(vgb_189, target_2)
and func_3(vgb_189, target_3)
and func_4(vgb_189, vlen_194, target_4)
and func_5(vgb_189, vlen_194, vofs_195, target_5)
and func_6(vofs_195, target_6)
and func_7(vofs_195, target_7)
and func_8(vofs_195, vframe_width_198, target_8)
and func_9(vlen_194, vofs_195, vframe_width_198, target_9)
and vgb_189.getType().hasName("GetByteContext")
and vlen_194.getType().hasName("unsigned char")
and vofs_195.getType().hasName("int")
and vframe_width_198.getType().hasName("int")
and vgb_189.(LocalVariable).getFunction() = func
and vlen_194.(LocalVariable).getFunction() = func
and vofs_195.(LocalVariable).getFunction() = func
and vframe_width_198.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
