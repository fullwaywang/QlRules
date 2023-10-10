/**
 * @name ffmpeg-79a98294da6cd85f8c86b34764c5e0c43b09eea3-read_sbr_data
 * @id cpp/ffmpeg/79a98294da6cd85f8c86b34764c5e0c43b09eea3/read-sbr-data
 * @description ffmpeg-79a98294da6cd85f8c86b34764c5e0c43b09eea3-libavcodec/aacsbr.c-read_sbr_data CVE-2015-6820
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vsbr_1017, Parameter vid_aac_1018, FunctionCall target_1, LogicalOrExpr target_2, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="id_aac"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsbr_1017
		and target_0.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vid_aac_1018
		and (func.getEntryPoint().(BlockStmt).getStmt(1)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(1).getFollowingStmt()=target_0)
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getArgument(1).(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vsbr_1017, FunctionCall target_1) {
		target_1.getTarget().hasName("read_sbr_single_channel_element")
		and target_1.getArgument(0).(VariableAccess).getTarget().getType().hasName("AACContext *")
		and target_1.getArgument(1).(VariableAccess).getTarget()=vsbr_1017
		and target_1.getArgument(2).(VariableAccess).getTarget().getType().hasName("GetBitContext *")
}

predicate func_2(Parameter vid_aac_1018, LogicalOrExpr target_2) {
		target_2.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vid_aac_1018
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vid_aac_1018
}

from Function func, Parameter vsbr_1017, Parameter vid_aac_1018, FunctionCall target_1, LogicalOrExpr target_2
where
not func_0(vsbr_1017, vid_aac_1018, target_1, target_2, func)
and func_1(vsbr_1017, target_1)
and func_2(vid_aac_1018, target_2)
and vsbr_1017.getType().hasName("SpectralBandReplication *")
and vid_aac_1018.getType().hasName("int")
and vsbr_1017.getFunction() = func
and vid_aac_1018.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
