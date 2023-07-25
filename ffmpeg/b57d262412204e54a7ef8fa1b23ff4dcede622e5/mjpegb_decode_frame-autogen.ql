/**
 * @name ffmpeg-b57d262412204e54a7ef8fa1b23ff4dcede622e5-mjpegb_decode_frame
 * @id cpp/ffmpeg/b57d262412204e54a7ef8fa1b23ff4dcede622e5/mjpegb-decode-frame
 * @description ffmpeg-b57d262412204e54a7ef8fa1b23ff4dcede622e5-libavcodec/mjpegbdec.c-mjpegb_decode_frame CVE-2011-3947
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vbuf_end_47, Variable vbuf_ptr_47, ExprStmt target_5, MulExpr target_6, ExprStmt target_7, ExprStmt target_8, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vbuf_end_47
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vbuf_ptr_47
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(BinaryBitwiseOperation).getValue()="268435456"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="3199971767"
		and (func.getEntryPoint().(BlockStmt).getStmt(14)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(14).getFollowingStmt()=target_0)
		and target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation().isBefore(target_6.getLeftOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation())
		and target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation().isBefore(target_8.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_1(Variable vbuf_end_47, Variable vbuf_ptr_47, Variable vsos_offs_50, Variable vfield_size_51, PointerArithmeticOperation target_9, PointerArithmeticOperation target_10, ExprStmt target_11, MulExpr target_4) {
	exists(MulExpr target_1 |
		target_1.getLeftOperand().(Literal).getValue()="8"
		and target_1.getRightOperand().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vfield_size_51
		and target_1.getRightOperand().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vbuf_end_47
		and target_1.getRightOperand().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vbuf_ptr_47
		and target_1.getRightOperand().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vsos_offs_50
		and target_1.getRightOperand().(ConditionalExpr).getThen().(SubExpr).getLeftOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vbuf_end_47
		and target_1.getRightOperand().(ConditionalExpr).getThen().(SubExpr).getLeftOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vbuf_ptr_47
		and target_1.getRightOperand().(ConditionalExpr).getThen().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vsos_offs_50
		and target_1.getRightOperand().(ConditionalExpr).getElse().(VariableAccess).getTarget()=vfield_size_51
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("init_get_bits")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="gb"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("MJpegDecodeContext *")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vbuf_ptr_47
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vsos_offs_50
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof MulExpr
		and target_9.getLeftOperand().(VariableAccess).getLocation().isBefore(target_1.getRightOperand().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation())
		and target_10.getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getRightOperand().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation())
		and target_1.getRightOperand().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_11.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(SubExpr).getRightOperand().(VariableAccess).getLocation())
		and target_1.getRightOperand().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_4.getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_3(Variable vbuf_ptr_47, Variable vsos_offs_50, Variable vfield_size_51, VariableAccess target_3) {
		target_3.getTarget()=vfield_size_51
		and target_3.getParent().(MulExpr).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("init_get_bits")
		and target_3.getParent().(MulExpr).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="gb"
		and target_3.getParent().(MulExpr).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("MJpegDecodeContext *")
		and target_3.getParent().(MulExpr).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vbuf_ptr_47
		and target_3.getParent().(MulExpr).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vsos_offs_50
		and target_3.getParent().(MulExpr).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof MulExpr
}

predicate func_4(Variable vbuf_ptr_47, Variable vsos_offs_50, Variable vfield_size_51, MulExpr target_4) {
		target_4.getLeftOperand().(VariableAccess).getTarget()=vfield_size_51
		and target_4.getRightOperand() instanceof Literal
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("init_get_bits")
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="gb"
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("MJpegDecodeContext *")
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vbuf_ptr_47
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vsos_offs_50
}

predicate func_5(Variable vbuf_end_47, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbuf_end_47
		and target_5.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("const uint8_t *")
		and target_5.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_6(Variable vbuf_end_47, Variable vbuf_ptr_47, MulExpr target_6) {
		target_6.getLeftOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vbuf_end_47
		and target_6.getLeftOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vbuf_ptr_47
		and target_6.getRightOperand().(Literal).getValue()="8"
}

predicate func_7(Variable vbuf_ptr_47, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbuf_ptr_47
		and target_7.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget().getType().hasName("const uint8_t *")
}

predicate func_8(Variable vbuf_end_47, Variable vbuf_ptr_47, ExprStmt target_8) {
		target_8.getExpr().(FunctionCall).getTarget().hasName("init_get_bits")
		and target_8.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("GetBitContext")
		and target_8.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuf_ptr_47
		and target_8.getExpr().(FunctionCall).getArgument(2).(MulExpr).getLeftOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vbuf_end_47
		and target_8.getExpr().(FunctionCall).getArgument(2).(MulExpr).getLeftOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vbuf_ptr_47
		and target_8.getExpr().(FunctionCall).getArgument(2).(MulExpr).getRightOperand().(Literal).getValue()="8"
}

predicate func_9(Variable vbuf_end_47, Variable vbuf_ptr_47, PointerArithmeticOperation target_9) {
		target_9.getLeftOperand().(VariableAccess).getTarget()=vbuf_end_47
		and target_9.getRightOperand().(VariableAccess).getTarget()=vbuf_ptr_47
}

predicate func_10(Variable vbuf_ptr_47, Variable vsos_offs_50, PointerArithmeticOperation target_10) {
		target_10.getAnOperand().(VariableAccess).getTarget()=vbuf_ptr_47
		and target_10.getAnOperand().(VariableAccess).getTarget()=vsos_offs_50
}

predicate func_11(Variable vsos_offs_50, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="mjpb_skiptosod"
		and target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("MJpegDecodeContext *")
		and target_11.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_11.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vsos_offs_50
		and target_11.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(FunctionCall).getTarget().hasName("show_bits")
		and target_11.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="gb"
		and target_11.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("MJpegDecodeContext *")
		and target_11.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(FunctionCall).getArgument(1).(Literal).getValue()="16"
}

from Function func, Variable vbuf_end_47, Variable vbuf_ptr_47, Variable vsos_offs_50, Variable vfield_size_51, VariableAccess target_3, MulExpr target_4, ExprStmt target_5, MulExpr target_6, ExprStmt target_7, ExprStmt target_8, PointerArithmeticOperation target_9, PointerArithmeticOperation target_10, ExprStmt target_11
where
not func_0(vbuf_end_47, vbuf_ptr_47, target_5, target_6, target_7, target_8, func)
and not func_1(vbuf_end_47, vbuf_ptr_47, vsos_offs_50, vfield_size_51, target_9, target_10, target_11, target_4)
and func_3(vbuf_ptr_47, vsos_offs_50, vfield_size_51, target_3)
and func_4(vbuf_ptr_47, vsos_offs_50, vfield_size_51, target_4)
and func_5(vbuf_end_47, target_5)
and func_6(vbuf_end_47, vbuf_ptr_47, target_6)
and func_7(vbuf_ptr_47, target_7)
and func_8(vbuf_end_47, vbuf_ptr_47, target_8)
and func_9(vbuf_end_47, vbuf_ptr_47, target_9)
and func_10(vbuf_ptr_47, vsos_offs_50, target_10)
and func_11(vsos_offs_50, target_11)
and vbuf_end_47.getType().hasName("const uint8_t *")
and vbuf_ptr_47.getType().hasName("const uint8_t *")
and vsos_offs_50.getType().hasName("uint32_t")
and vfield_size_51.getType().hasName("uint32_t")
and vbuf_end_47.(LocalVariable).getFunction() = func
and vbuf_ptr_47.(LocalVariable).getFunction() = func
and vsos_offs_50.(LocalVariable).getFunction() = func
and vfield_size_51.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
