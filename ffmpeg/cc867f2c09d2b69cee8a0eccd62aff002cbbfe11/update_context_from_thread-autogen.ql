/**
 * @name ffmpeg-cc867f2c09d2b69cee8a0eccd62aff002cbbfe11-update_context_from_thread
 * @id cpp/ffmpeg/cc867f2c09d2b69cee8a0eccd62aff002cbbfe11/update-context-from-thread
 * @description ffmpeg-cc867f2c09d2b69cee8a0eccd62aff002cbbfe11-libavcodec/pthread_frame.c-update_context_from_thread CVE-2022-48434
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vsrc_262, Parameter vdst_262, LogicalAndExpr target_3, ExprStmt target_0) {
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="hwaccel"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdst_262
		and target_0.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="hwaccel"
		and target_0.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsrc_262
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
}

predicate func_1(Parameter vsrc_262, Parameter vdst_262, LogicalAndExpr target_3, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="hwaccel_context"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdst_262
		and target_1.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="hwaccel_context"
		and target_1.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsrc_262
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
}

predicate func_2(Parameter vsrc_262, Parameter vdst_262, LogicalAndExpr target_3, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="hwaccel_priv_data"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="internal"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdst_262
		and target_2.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="hwaccel_priv_data"
		and target_2.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="internal"
		and target_2.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsrc_262
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
}

predicate func_3(Parameter vsrc_262, Parameter vdst_262, LogicalAndExpr target_3) {
		target_3.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vdst_262
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vsrc_262
		and target_3.getAnOperand().(LogicalOrExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="update_thread_context"
}

from Function func, Parameter vsrc_262, Parameter vdst_262, ExprStmt target_0, ExprStmt target_1, ExprStmt target_2, LogicalAndExpr target_3
where
func_0(vsrc_262, vdst_262, target_3, target_0)
and func_1(vsrc_262, vdst_262, target_3, target_1)
and func_2(vsrc_262, vdst_262, target_3, target_2)
and func_3(vsrc_262, vdst_262, target_3)
and vsrc_262.getType().hasName("AVCodecContext *")
and vdst_262.getType().hasName("AVCodecContext *")
and vsrc_262.getParentScope+() = func
and vdst_262.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
