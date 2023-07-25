/**
 * @name ffmpeg-39bbdebb1ed8eb9c9b0cd6db85afde6ba89d86e4-destroy_buffers
 * @id cpp/ffmpeg/39bbdebb1ed8eb9c9b0cd6db85afde6ba89d86e4/destroy-buffers
 * @description ffmpeg-39bbdebb1ed8eb9c9b0cd6db85afde6ba89d86e4-libavcodec/sanm.c-destroy_buffers CVE-2015-6822
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctx_450, ExprStmt target_1, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("init_sizes")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_450
		and target_0.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_0.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vctx_450, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="frm0_size"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_450
		and target_1.getExpr().(AssignExpr).getRValue().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="frm1_size"
		and target_1.getExpr().(AssignExpr).getRValue().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_450
		and target_1.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="frm2_size"
		and target_1.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_450
		and target_1.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(AssignExpr).getRValue().(Literal).getValue()="0"
}

from Function func, Parameter vctx_450, ExprStmt target_1
where
not func_0(vctx_450, target_1, func)
and func_1(vctx_450, target_1)
and vctx_450.getType().hasName("SANMVideoContext *")
and vctx_450.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
