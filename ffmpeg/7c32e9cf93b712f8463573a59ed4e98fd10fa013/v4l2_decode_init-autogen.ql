/**
 * @name ffmpeg-7c32e9cf93b712f8463573a59ed4e98fd10fa013-v4l2_decode_init
 * @id cpp/ffmpeg/7c32e9cf93b712f8463573a59ed4e98fd10fa013/v4l2-decode-init
 * @description ffmpeg-7c32e9cf93b712f8463573a59ed4e98fd10fa013-libavcodec/v4l2_m2m_dec.c-v4l2_decode_init CVE-2020-22038
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vs_180, VariableAccess target_2, ExprStmt target_0) {
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="self_ref"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_180
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
}

predicate func_1(Variable vpriv_181, VariableAccess target_2, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("av_buffer_unref")
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="context_ref"
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpriv_181
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
}

predicate func_2(Variable vret_182, VariableAccess target_2) {
		target_2.getTarget()=vret_182
}

from Function func, Variable vs_180, Variable vpriv_181, Variable vret_182, ExprStmt target_0, ExprStmt target_1, VariableAccess target_2
where
func_0(vs_180, target_2, target_0)
and func_1(vpriv_181, target_2, target_1)
and func_2(vret_182, target_2)
and vs_180.getType().hasName("V4L2m2mContext *")
and vpriv_181.getType().hasName("V4L2m2mPriv *")
and vret_182.getType().hasName("int")
and vs_180.getParentScope+() = func
and vpriv_181.getParentScope+() = func
and vret_182.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
