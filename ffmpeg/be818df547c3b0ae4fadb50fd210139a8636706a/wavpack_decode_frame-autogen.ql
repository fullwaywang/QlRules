/**
 * @name ffmpeg-be818df547c3b0ae4fadb50fd210139a8636706a-wavpack_decode_frame
 * @id cpp/ffmpeg/be818df547c3b0ae4fadb50fd210139a8636706a/wavpack-decode-frame
 * @description ffmpeg-be818df547c3b0ae4fadb50fd210139a8636706a-libavcodec/wavpack.c-wavpack_decode_frame CVE-2013-0853
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vs_1173, ExprStmt target_3, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue() instanceof ValueFieldAccess
		and target_0.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="samples"
		and target_0.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1173
		and target_0.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_0)
		and target_3.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vs_1173, ValueFieldAccess target_2) {
		target_2.getTarget().getName()="nb_samples"
		and target_2.getQualifier().(PointerFieldAccess).getTarget().getName()="frame"
		and target_2.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1173
}

predicate func_3(Variable vs_1173, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("AVCodecContext *")
		and target_3.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_3.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Invalid number of samples: %d\n"
		and target_3.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="samples"
		and target_3.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1173
}

from Function func, Variable vs_1173, ValueFieldAccess target_2, ExprStmt target_3
where
not func_0(vs_1173, target_3, func)
and func_2(vs_1173, target_2)
and func_3(vs_1173, target_3)
and vs_1173.getType().hasName("WavpackContext *")
and vs_1173.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
