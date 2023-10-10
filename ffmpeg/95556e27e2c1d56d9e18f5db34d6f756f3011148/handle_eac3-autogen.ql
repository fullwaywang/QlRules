/**
 * @name ffmpeg-95556e27e2c1d56d9e18f5db34d6f756f3011148-handle_eac3
 * @id cpp/ffmpeg/95556e27e2c1d56d9e18f5db34d6f756f3011148/handle-eac3
 * @description ffmpeg-95556e27e2c1d56d9e18f5db34d6f756f3011148-libavformat/movenc.c-handle_eac3 CVE-2018-13300
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vmov_391, ExprStmt target_2, ExprStmt target_3) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="fc"
		and target_0.getQualifier().(VariableAccess).getTarget()=vmov_391
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getQualifier().(VariableAccess).getLocation())
		and target_0.getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vtrack_391, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="par"
		and target_1.getQualifier().(VariableAccess).getTarget()=vtrack_391
}

predicate func_2(Parameter vmov_391, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmov_391
		and target_2.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="24"
		and target_2.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Dropping invalid packet from start of the stream\n"
}

predicate func_3(Parameter vmov_391, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("avpriv_request_sample")
		and target_3.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="fc"
		and target_3.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmov_391
		and target_3.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Multiple non EAC3 independent substreams"
}

from Function func, Parameter vtrack_391, Parameter vmov_391, PointerFieldAccess target_1, ExprStmt target_2, ExprStmt target_3
where
not func_0(vmov_391, target_2, target_3)
and func_1(vtrack_391, target_1)
and func_2(vmov_391, target_2)
and func_3(vmov_391, target_3)
and vtrack_391.getType().hasName("MOVTrack *")
and vmov_391.getType().hasName("MOVMuxContext *")
and vtrack_391.getParentScope+() = func
and vmov_391.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
