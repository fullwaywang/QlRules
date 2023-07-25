/**
 * @name ffmpeg-8f4c3e4b92212d98f5b9ca2dee13e076effe9589-apng_encode_frame
 * @id cpp/ffmpeg/8f4c3e4b92212d98f5b9ca2dee13e076effe9589/apng-encode-frame
 * @description ffmpeg-8f4c3e4b92212d98f5b9ca2dee13e076effe9589-libavcodec/pngenc.c-apng_encode_frame CVE-2016-2327
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vs_712, ExprStmt target_2, NotExpr target_3, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="last_frame"
		and target_1.getQualifier().(VariableAccess).getTarget()=vs_712
		and target_2.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getQualifier().(VariableAccess).getLocation())
		and target_1.getQualifier().(VariableAccess).getLocation().isBefore(target_3.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_2(Variable vs_712, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("av_frame_copy")
		and target_2.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="last_frame"
		and target_2.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_712
}

predicate func_3(Variable vs_712, NotExpr target_3) {
		target_3.getOperand().(PointerFieldAccess).getTarget().getName()="prev_frame"
		and target_3.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_712
}

from Function func, Variable vs_712, PointerFieldAccess target_1, ExprStmt target_2, NotExpr target_3
where
func_1(vs_712, target_2, target_3, target_1)
and func_2(vs_712, target_2)
and func_3(vs_712, target_3)
and vs_712.getType().hasName("PNGEncContext *")
and vs_712.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
