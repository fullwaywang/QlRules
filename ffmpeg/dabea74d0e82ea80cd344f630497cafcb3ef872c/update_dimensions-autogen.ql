/**
 * @name ffmpeg-dabea74d0e82ea80cd344f630497cafcb3ef872c-update_dimensions
 * @id cpp/ffmpeg/dabea74d0e82ea80cd344f630497cafcb3ef872c/update-dimensions
 * @description ffmpeg-dabea74d0e82ea80cd344f630497cafcb3ef872c-libavcodec/vp8.c-update_dimensions CVE-2015-6761
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_149, Variable vavctx_151, PointerFieldAccess target_0) {
		target_0.getTarget().getName()="thread_count"
		and target_0.getQualifier().(VariableAccess).getTarget()=vavctx_151
		and target_0.getParent().(GTExpr).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="num_coeff_partitions"
		and target_0.getParent().(GTExpr).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_149
}

predicate func_1(Parameter vs_149, Variable vavctx_151, ConditionalExpr target_1) {
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="num_coeff_partitions"
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_149
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="thread_count"
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_151
		and target_1.getThen().(PointerFieldAccess).getTarget().getName()="thread_count"
		and target_1.getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_151
		and target_1.getElse().(PointerFieldAccess).getTarget().getName()="num_coeff_partitions"
		and target_1.getElse().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_149
}

from Function func, Parameter vs_149, Variable vavctx_151, PointerFieldAccess target_0, ConditionalExpr target_1
where
func_0(vs_149, vavctx_151, target_0)
and func_1(vs_149, vavctx_151, target_1)
and vs_149.getType().hasName("VP8Context *")
and vavctx_151.getType().hasName("AVCodecContext *")
and vs_149.getParentScope+() = func
and vavctx_151.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
