/**
 * @name ffmpeg-327ff82bac3081d918dceb4931c77e25d0a1480d-bmp_decode_frame
 * @id cpp/ffmpeg/327ff82bac3081d918dceb4931c77e25d0a1480d/bmp-decode-frame
 * @description ffmpeg-327ff82bac3081d918dceb4931c77e25d0a1480d-libavcodec/bmp.c-bmp_decode_frame CVE-2013-2496
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vbuf_40, Variable vdsize_53, ExprStmt target_5, ExprStmt target_6, ExprStmt target_7) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("bytestream2_init")
		and target_0.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("GetByteContext")
		and target_0.getArgument(1).(VariableAccess).getTarget()=vbuf_40
		and target_0.getArgument(2).(VariableAccess).getTarget()=vdsize_53
		and target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getArgument(1).(VariableAccess).getLocation())
		and target_0.getArgument(1).(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_7.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation().isBefore(target_0.getArgument(2).(VariableAccess).getLocation()))
}

predicate func_1(Variable vp_44, Variable vdepth_47, Parameter vavctx_36, LogicalOrExpr target_8, ExprStmt target_9, ExprStmt target_10, ExprStmt target_11, SwitchStmt target_12, ExprStmt target_13) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("ff_msrle_decode")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_36
		and target_1.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vp_44
		and target_1.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vdepth_47
		and target_1.getExpr().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("GetByteContext")
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_9.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_1.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_10.getExpr().(AssignPointerAddExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_11.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_1.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_12.getExpr().(VariableAccess).getLocation())
		and target_13.getExpr().(AssignPointerAddExpr).getRValue().(MulExpr).getRightOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

/*predicate func_2(Variable vbuf_40, Variable vp_44, Variable vdepth_47, Variable vdsize_53, Parameter vavctx_36) {
	exists(AddressOfExpr target_2 |
		target_2.getOperand().(VariableAccess).getType().hasName("GetByteContext")
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ff_msrle_decode")
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_36
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vp_44
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vdepth_47
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vbuf_40
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vdsize_53)
}

*/
predicate func_3(Variable vbuf_40, Variable vp_44, Variable vdepth_47, Variable vdsize_53, Parameter vavctx_36, VariableAccess target_3) {
		target_3.getTarget()=vbuf_40
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ff_msrle_decode")
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_36
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vp_44
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vdepth_47
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vdsize_53
}

/*predicate func_4(Variable vbuf_40, Variable vp_44, Variable vdepth_47, Variable vdsize_53, Parameter vavctx_36, VariableAccess target_4) {
		target_4.getTarget()=vdsize_53
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ff_msrle_decode")
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_36
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vp_44
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vdepth_47
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vbuf_40
}

*/
predicate func_5(Variable vbuf_40, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbuf_40
		and target_5.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("const uint8_t *")
		and target_5.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("unsigned int")
}

predicate func_6(Variable vbuf_40, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("uint8_t *")
		and target_6.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_6.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(Literal).getValue()="8"
		and target_6.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(Literal).getValue()="0"
		and target_6.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuf_40
		and target_6.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
		and target_6.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="7"
}

predicate func_7(Variable vdsize_53, Parameter vavctx_36, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_36
		and target_7.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_7.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="not enough data (%d < %d)\n"
		and target_7.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vdsize_53
		and target_7.getExpr().(FunctionCall).getArgument(4).(MulExpr).getLeftOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_7.getExpr().(FunctionCall).getArgument(4).(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_7.getExpr().(FunctionCall).getArgument(4).(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_36
}

predicate func_8(LogicalOrExpr target_8) {
		target_8.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("BiCompression")
		and target_8.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("BiCompression")
}

predicate func_9(Variable vp_44, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="linesize"
		and target_9.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_44
		and target_9.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_9.getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="linesize"
		and target_9.getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_44
		and target_9.getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

predicate func_10(Variable vp_44, Parameter vavctx_36, ExprStmt target_10) {
		target_10.getExpr().(AssignPointerAddExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_10.getExpr().(AssignPointerAddExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_44
		and target_10.getExpr().(AssignPointerAddExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_10.getExpr().(AssignPointerAddExpr).getRValue().(MulExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="linesize"
		and target_10.getExpr().(AssignPointerAddExpr).getRValue().(MulExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_44
		and target_10.getExpr().(AssignPointerAddExpr).getRValue().(MulExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_10.getExpr().(AssignPointerAddExpr).getRValue().(MulExpr).getRightOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_10.getExpr().(AssignPointerAddExpr).getRValue().(MulExpr).getRightOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_36
		and target_10.getExpr().(AssignPointerAddExpr).getRValue().(MulExpr).getRightOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

predicate func_11(Variable vdepth_47, Parameter vavctx_36, ExprStmt target_11) {
		target_11.getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_11.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_36
		and target_11.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_11.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Incorrect number of colors - %X for bitdepth %d\n"
		and target_11.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("int")
		and target_11.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vdepth_47
}

predicate func_12(Variable vbuf_40, Variable vdepth_47, Parameter vavctx_36, SwitchStmt target_12) {
		target_12.getExpr().(VariableAccess).getTarget()=vdepth_47
		and target_12.getStmt().(BlockStmt).getStmt(0).(SwitchCase).getExpr().(Literal).getValue()="1"
		and target_12.getStmt().(BlockStmt).getStmt(1).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_12.getStmt().(BlockStmt).getStmt(1).(ForStmt).getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_12.getStmt().(BlockStmt).getStmt(1).(ForStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_12.getStmt().(BlockStmt).getStmt(1).(ForStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_12.getStmt().(BlockStmt).getStmt(1).(ForStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_36
		and target_12.getStmt().(BlockStmt).getStmt(1).(ForStmt).getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_12.getStmt().(BlockStmt).getStmt(1).(ForStmt).getStmt().(BlockStmt).getStmt(1).(ForStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_12.getStmt().(BlockStmt).getStmt(1).(ForStmt).getStmt().(BlockStmt).getStmt(1).(ForStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_12.getStmt().(BlockStmt).getStmt(1).(ForStmt).getStmt().(BlockStmt).getStmt(1).(ForStmt).getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_12.getStmt().(BlockStmt).getStmt(1).(ForStmt).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vbuf_40
		and target_12.getStmt().(BlockStmt).getStmt(1).(ForStmt).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_13(Variable vp_44, Parameter vavctx_36, ExprStmt target_13) {
		target_13.getExpr().(AssignPointerAddExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_13.getExpr().(AssignPointerAddExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_44
		and target_13.getExpr().(AssignPointerAddExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_13.getExpr().(AssignPointerAddExpr).getRValue().(MulExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="linesize"
		and target_13.getExpr().(AssignPointerAddExpr).getRValue().(MulExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_44
		and target_13.getExpr().(AssignPointerAddExpr).getRValue().(MulExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_13.getExpr().(AssignPointerAddExpr).getRValue().(MulExpr).getRightOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_13.getExpr().(AssignPointerAddExpr).getRValue().(MulExpr).getRightOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_36
		and target_13.getExpr().(AssignPointerAddExpr).getRValue().(MulExpr).getRightOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

from Function func, Variable vbuf_40, Variable vp_44, Variable vdepth_47, Variable vdsize_53, Parameter vavctx_36, VariableAccess target_3, ExprStmt target_5, ExprStmt target_6, ExprStmt target_7, LogicalOrExpr target_8, ExprStmt target_9, ExprStmt target_10, ExprStmt target_11, SwitchStmt target_12, ExprStmt target_13
where
not func_0(vbuf_40, vdsize_53, target_5, target_6, target_7)
and not func_1(vp_44, vdepth_47, vavctx_36, target_8, target_9, target_10, target_11, target_12, target_13)
and func_3(vbuf_40, vp_44, vdepth_47, vdsize_53, vavctx_36, target_3)
and func_5(vbuf_40, target_5)
and func_6(vbuf_40, target_6)
and func_7(vdsize_53, vavctx_36, target_7)
and func_8(target_8)
and func_9(vp_44, target_9)
and func_10(vp_44, vavctx_36, target_10)
and func_11(vdepth_47, vavctx_36, target_11)
and func_12(vbuf_40, vdepth_47, vavctx_36, target_12)
and func_13(vp_44, vavctx_36, target_13)
and vbuf_40.getType().hasName("const uint8_t *")
and vp_44.getType().hasName("AVFrame *")
and vdepth_47.getType().hasName("unsigned int")
and vdsize_53.getType().hasName("int")
and vavctx_36.getType().hasName("AVCodecContext *")
and vbuf_40.(LocalVariable).getFunction() = func
and vp_44.(LocalVariable).getFunction() = func
and vdepth_47.(LocalVariable).getFunction() = func
and vdsize_53.(LocalVariable).getFunction() = func
and vavctx_36.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
