/**
 * @name ffmpeg-608708009f69ba4cecebf05120c696167494c897-adpcm_decode_frame
 * @id cpp/ffmpeg/608708009f69ba4cecebf05120c696167494c897/adpcm-decode-frame
 * @description ffmpeg-608708009f69ba4cecebf05120c696167494c897-libavcodec/adpcm.c-adpcm_decode_frame CVE-2012-0852
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vavctx_513, ExprStmt target_1, RelationalOperation target_2) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="channels"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_513
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="2"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="3199971767"
		and target_1.getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vavctx_513, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("xa_decode")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("short *")
		and target_1.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("const uint8_t *")
		and target_1.getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="status"
		and target_1.getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("ADPCMDecodeContext *")
		and target_1.getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_1.getExpr().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="status"
		and target_1.getExpr().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("ADPCMDecodeContext *")
		and target_1.getExpr().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_1.getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="channels"
		and target_1.getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_513
}

predicate func_2(Parameter vavctx_513, RelationalOperation target_2) {
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getLesserOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_2.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="channels"
		and target_2.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_513
}

from Function func, Parameter vavctx_513, ExprStmt target_1, RelationalOperation target_2
where
not func_0(vavctx_513, target_1, target_2)
and func_1(vavctx_513, target_1)
and func_2(vavctx_513, target_2)
and vavctx_513.getType().hasName("AVCodecContext *")
and vavctx_513.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
