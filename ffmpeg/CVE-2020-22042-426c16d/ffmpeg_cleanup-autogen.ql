/**
 * @name ffmpeg-426c16d61a9b5056a157a1a2a057a4e4d13eef84-ffmpeg_cleanup
 * @id cpp/ffmpeg/426c16d61a9b5056a157a1a2a057a4e4d13eef84/ffmpeg-cleanup
 * @description ffmpeg-426c16d61a9b5056a157a1a2a057a4e4d13eef84-fftools/ffmpeg.c-ffmpeg_cleanup CVE-2020-22042
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vofilter_529, AddressOfExpr target_1) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("avfilter_inout_free")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="out_tmp"
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vofilter_529
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vofilter_529, AddressOfExpr target_1) {
		target_1.getOperand().(PointerFieldAccess).getTarget().getName()="name"
		and target_1.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vofilter_529
}

from Function func, Variable vofilter_529, AddressOfExpr target_1
where
not func_0(vofilter_529, target_1)
and func_1(vofilter_529, target_1)
and vofilter_529.getType().hasName("OutputFilter *")
and vofilter_529.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
