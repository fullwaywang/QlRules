/**
 * @name ffmpeg-7c32e9cf93b712f8463573a59ed4e98fd10fa013-v4l2_m2m_destroy_context
 * @id cpp/ffmpeg/7c32e9cf93b712f8463573a59ed4e98fd10fa013/v4l2-m2m-destroy-context
 * @description ffmpeg-7c32e9cf93b712f8463573a59ed4e98fd10fa013-libavcodec/v4l2_m2m.c-v4l2_m2m_destroy_context CVE-2020-22038
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vs_326, AddressOfExpr target_1, ExprStmt target_2, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("av_packet_unref")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="buf_pkt"
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_326
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_0)
		and target_1.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vs_326, AddressOfExpr target_1) {
		target_1.getOperand().(PointerFieldAccess).getTarget().getName()="frame"
		and target_1.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_326
}

predicate func_2(Variable vs_326, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("av_free")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_326
}

from Function func, Variable vs_326, AddressOfExpr target_1, ExprStmt target_2
where
not func_0(vs_326, target_1, target_2, func)
and func_1(vs_326, target_1)
and func_2(vs_326, target_2)
and vs_326.getType().hasName("V4L2m2mContext *")
and vs_326.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
