/**
 * @name ffmpeg-d442c4462a2692e27a24e1a9d0eb6f18725c7bd8-decode_init
 * @id cpp/ffmpeg/d442c4462a2692e27a24e1a9d0eb6f18725c7bd8/decode-init
 * @description ffmpeg-d442c4462a2692e27a24e1a9d0eb6f18725c7bd8-libavcodec/wmalosslessdec.c-decode_init CVE-2012-2792
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Function func) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(VariableAccess).getType().hasName("int")
		and target_1.getRValue() instanceof FunctionCall
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Parameter vavctx_171, RelationalOperation target_7, Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("int")
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="12"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log_missing_feature")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_171
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="big-bits block sizes"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="1"
		and target_2.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="3199971767"
		and (func.getEntryPoint().(BlockStmt).getStmt(12)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(12).getFollowingStmt()=target_2)
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_7.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Variable vs_173, ExprStmt target_8, ExprStmt target_9, Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="samples_per_frame"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_173
		and target_3.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_3.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(VariableAccess).getType().hasName("int")
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_3)
		and target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_5(Parameter vavctx_171, Variable vs_173, FunctionCall target_5) {
		target_5.getTarget().hasName("ff_wma_get_frame_len_bits")
		and target_5.getArgument(0).(PointerFieldAccess).getTarget().getName()="sample_rate"
		and target_5.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_171
		and target_5.getArgument(1).(Literal).getValue()="3"
		and target_5.getArgument(2).(PointerFieldAccess).getTarget().getName()="decode_flags"
		and target_5.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_173
}

predicate func_7(Parameter vavctx_171, RelationalOperation target_7) {
		 (target_7 instanceof GTExpr or target_7 instanceof LTExpr)
		and target_7.getLesserOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_7.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="channels"
		and target_7.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_171
}

predicate func_8(Variable vs_173, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="len_prefix"
		and target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_173
		and target_8.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="decode_flags"
		and target_8.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_173
		and target_8.getExpr().(AssignExpr).getRValue().(BitwiseAndExpr).getRightOperand().(HexLiteral).getValue()="64"
}

predicate func_9(Variable vs_173, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="samples_per_frame"
		and target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_173
		and target_9.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_9.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getRightOperand() instanceof FunctionCall
}

from Function func, Parameter vavctx_171, Variable vs_173, FunctionCall target_5, RelationalOperation target_7, ExprStmt target_8, ExprStmt target_9
where
not func_1(func)
and not func_2(vavctx_171, target_7, func)
and not func_3(vs_173, target_8, target_9, func)
and func_5(vavctx_171, vs_173, target_5)
and func_7(vavctx_171, target_7)
and func_8(vs_173, target_8)
and func_9(vs_173, target_9)
and vavctx_171.getType().hasName("AVCodecContext *")
and vs_173.getType().hasName("WmallDecodeCtx *")
and vavctx_171.getFunction() = func
and vs_173.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
