/**
 * @name ffmpeg-77d2ef13a8fa630e5081f14bde3fd20f84c90aec-matroska_merge_packets
 * @id cpp/ffmpeg/77d2ef13a8fa630e5081f14bde3fd20f84c90aec/matroska-merge-packets
 * @description ffmpeg-77d2ef13a8fa630e5081f14bde3fd20f84c90aec-libavformat/matroskadec.c-matroska_merge_packets CVE-2011-3504
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(VariableAccess).getType().hasName("void *")
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-12"
		and (func.getEntryPoint().(BlockStmt).getStmt(1)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(1).getFollowingStmt()=target_0))
}

predicate func_3(Parameter vout_1043, Parameter vin_1043, FunctionCall target_3) {
		target_3.getTarget().hasName("av_realloc")
		and target_3.getArgument(0).(PointerFieldAccess).getTarget().getName()="data"
		and target_3.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vout_1043
		and target_3.getArgument(1).(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_3.getArgument(1).(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vout_1043
		and target_3.getArgument(1).(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_3.getArgument(1).(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vin_1043
		and target_3.getParent().(AssignExpr).getRValue() = target_3
		and target_3.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="data"
		and target_3.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vout_1043
}

from Function func, Parameter vout_1043, Parameter vin_1043, FunctionCall target_3
where
not func_0(func)
and func_3(vout_1043, vin_1043, target_3)
and vout_1043.getType().hasName("AVPacket *")
and vin_1043.getType().hasName("AVPacket *")
and vout_1043.getFunction() = func
and vin_1043.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
