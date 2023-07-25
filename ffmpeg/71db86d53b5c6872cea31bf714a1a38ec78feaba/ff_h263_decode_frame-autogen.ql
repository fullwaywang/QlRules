/**
 * @name ffmpeg-71db86d53b5c6872cea31bf714a1a38ec78feaba-ff_h263_decode_frame
 * @id cpp/ffmpeg/71db86d53b5c6872cea31bf714a1a38ec78feaba/ff-h263-decode-frame
 * @description ffmpeg-71db86d53b5c6872cea31bf714a1a38ec78feaba-libavcodec/h263dec.c-ff_h263_decode_frame CVE-2011-3937
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vs_344, LogicalAndExpr target_4, ExprStmt target_5) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("ff_dct_common_init")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vs_344
		and target_4.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getArgument(0).(VariableAccess).getLocation())
		and target_0.getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vs_344, LogicalOrExpr target_6, ExprStmt target_7) {
	exists(IfStmt target_1 |
		target_1.getCondition().(LogicalAndExpr).getAnOperand().(Literal).getValue()="1"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="active_thread_type"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="avctx"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_344
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="1"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log_missing_feature")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="avctx"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_344
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Width/height/bit depth/chroma idc changing with threads is"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vavctx_338, AssignExpr target_3) {
		target_3.getLValue().(PointerFieldAccess).getTarget().getName()="coded_width"
		and target_3.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_338
		and target_3.getRValue() instanceof Literal
}

predicate func_4(Variable vs_344, Parameter vavctx_338, LogicalAndExpr target_4) {
		target_4.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="codec_id"
		and target_4.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_344
		and target_4.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="xvid_build"
		and target_4.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_344
		and target_4.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_4.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="idct_algo"
		and target_4.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_338
		and target_4.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_4.getAnOperand().(BitwiseAndExpr).getLeftOperand().(FunctionCall).getTarget().hasName("av_get_cpu_flags")
		and target_4.getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="1"
}

predicate func_5(Variable vs_344, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="picture_number"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_344
		and target_5.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_6(Variable vs_344, Parameter vavctx_338, LogicalOrExpr target_6) {
		target_6.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_344
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="coded_width"
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_338
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_344
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="coded_height"
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_338
}

predicate func_7(Variable vs_344, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="buffer"
		and target_7.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parse_context"
		and target_7.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_344
		and target_7.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

from Function func, Variable vs_344, Parameter vavctx_338, AssignExpr target_3, LogicalAndExpr target_4, ExprStmt target_5, LogicalOrExpr target_6, ExprStmt target_7
where
not func_0(vs_344, target_4, target_5)
and not func_1(vs_344, target_6, target_7)
and func_3(vavctx_338, target_3)
and func_4(vs_344, vavctx_338, target_4)
and func_5(vs_344, target_5)
and func_6(vs_344, vavctx_338, target_6)
and func_7(vs_344, target_7)
and vs_344.getType().hasName("MpegEncContext *")
and vavctx_338.getType().hasName("AVCodecContext *")
and vs_344.(LocalVariable).getFunction() = func
and vavctx_338.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
