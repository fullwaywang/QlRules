/**
 * @name ffmpeg-47b7c68ae54560e2308bdb6be4fb076c73b93081-decode_init
 * @id cpp/ffmpeg/47b7c68ae54560e2308bdb6be4fb076c73b93081/decode-init
 * @description ffmpeg-47b7c68ae54560e2308bdb6be4fb076c73b93081-libavcodec/utvideodec.c-decode_init CVE-2018-10001
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vc_915, PointerFieldAccess target_7, ExprStmt target_8, ExprStmt target_9) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="pro"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_915
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_0.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_7
		and target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vc_915, PointerFieldAccess target_7, ExprStmt target_9, ExprStmt target_10) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="pro"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_915
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_1.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_7
		and target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vc_915, BlockStmt target_11, ExprStmt target_12, ExprStmt target_13) {
	exists(LogicalAndExpr target_2 |
		target_2.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="pro"
		and target_2.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_915
		and target_2.getAnOperand() instanceof RelationalOperation
		and target_2.getParent().(IfStmt).getThen()=target_11
		and target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_13.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Variable vc_915, BlockStmt target_14, ExprStmt target_15, ExprStmt target_16) {
	exists(LogicalAndExpr target_3 |
		target_3.getAnOperand().(PointerFieldAccess).getTarget().getName()="pro"
		and target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_915
		and target_3.getAnOperand() instanceof EqualityOperation
		and target_3.getParent().(IfStmt).getThen()=target_14
		and target_15.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_16.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_4(Variable vc_915, EqualityOperation target_6, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="pro"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_915
		and target_4.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
}

predicate func_5(Parameter vavctx_913, BlockStmt target_11, RelationalOperation target_5) {
		 (target_5 instanceof GEExpr or target_5 instanceof LEExpr)
		and target_5.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="extradata_size"
		and target_5.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_913
		and target_5.getLesserOperand().(Literal).getValue()="16"
		and target_5.getParent().(IfStmt).getThen()=target_11
}

predicate func_6(Parameter vavctx_913, BlockStmt target_14, EqualityOperation target_6) {
		target_6.getAnOperand().(PointerFieldAccess).getTarget().getName()="extradata_size"
		and target_6.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_913
		and target_6.getAnOperand().(Literal).getValue()="8"
		and target_6.getParent().(IfStmt).getThen()=target_14
}

predicate func_7(Parameter vavctx_913, PointerFieldAccess target_7) {
		target_7.getTarget().getName()="codec_tag"
		and target_7.getQualifier().(VariableAccess).getTarget()=vavctx_913
}

predicate func_8(Variable vc_915, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="planes"
		and target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_915
		and target_8.getExpr().(AssignExpr).getRValue().(Literal).getValue()="3"
}

predicate func_9(Variable vc_915, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="planes"
		and target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_915
		and target_9.getExpr().(AssignExpr).getRValue().(Literal).getValue()="4"
}

predicate func_10(Variable vc_915, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="planes"
		and target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_915
		and target_10.getExpr().(AssignExpr).getRValue().(Literal).getValue()="3"
}

predicate func_11(Parameter vavctx_913, BlockStmt target_11) {
		target_11.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_11.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_913
		and target_11.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="48"
		and target_11.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Encoder version %d.%d.%d.%d\n"
		and target_11.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="extradata"
		and target_11.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_913
		and target_11.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ArrayExpr).getArrayOffset().(Literal).getValue()="3"
		and target_11.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="extradata"
		and target_11.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_913
		and target_11.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_11.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="extradata"
		and target_11.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_913
		and target_11.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_11.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="extradata"
		and target_11.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_913
		and target_11.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

predicate func_12(Parameter vavctx_913, Variable vc_915, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="slices"
		and target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_915
		and target_12.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="extradata"
		and target_12.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_913
		and target_12.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="9"
		and target_12.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="1"
}

predicate func_13(Parameter vavctx_913, Variable vc_915, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="frame_info_size"
		and target_13.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_915
		and target_13.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="l"
		and target_13.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="extradata"
		and target_13.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_913
		and target_13.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="8"
}

predicate func_14(Parameter vavctx_913, BlockStmt target_14) {
		target_14.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_14.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_913
		and target_14.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="48"
		and target_14.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Encoder version %d.%d.%d.%d\n"
		and target_14.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="extradata"
		and target_14.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_913
		and target_14.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ArrayExpr).getArrayOffset().(Literal).getValue()="3"
		and target_14.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="extradata"
		and target_14.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_913
		and target_14.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_14.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="extradata"
		and target_14.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_913
		and target_14.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_14.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="extradata"
		and target_14.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_913
		and target_14.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

predicate func_15(Variable vc_915, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="interlaced"
		and target_15.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_915
		and target_15.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_15.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_915
		and target_15.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getRightOperand().(HexLiteral).getValue()="2048"
}

predicate func_16(Variable vc_915, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="interlaced"
		and target_16.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_915
		and target_16.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

from Function func, Parameter vavctx_913, Variable vc_915, ExprStmt target_4, RelationalOperation target_5, EqualityOperation target_6, PointerFieldAccess target_7, ExprStmt target_8, ExprStmt target_9, ExprStmt target_10, BlockStmt target_11, ExprStmt target_12, ExprStmt target_13, BlockStmt target_14, ExprStmt target_15, ExprStmt target_16
where
not func_0(vc_915, target_7, target_8, target_9)
and not func_1(vc_915, target_7, target_9, target_10)
and not func_2(vc_915, target_11, target_12, target_13)
and not func_3(vc_915, target_14, target_15, target_16)
and func_4(vc_915, target_6, target_4)
and func_5(vavctx_913, target_11, target_5)
and func_6(vavctx_913, target_14, target_6)
and func_7(vavctx_913, target_7)
and func_8(vc_915, target_8)
and func_9(vc_915, target_9)
and func_10(vc_915, target_10)
and func_11(vavctx_913, target_11)
and func_12(vavctx_913, vc_915, target_12)
and func_13(vavctx_913, vc_915, target_13)
and func_14(vavctx_913, target_14)
and func_15(vc_915, target_15)
and func_16(vc_915, target_16)
and vavctx_913.getType().hasName("AVCodecContext *")
and vc_915.getType().hasName("UtvideoContext *const")
and vavctx_913.getParentScope+() = func
and vc_915.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
