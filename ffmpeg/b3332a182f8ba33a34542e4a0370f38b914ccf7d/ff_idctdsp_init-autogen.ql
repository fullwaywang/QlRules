/**
 * @name ffmpeg-b3332a182f8ba33a34542e4a0370f38b914ccf7d-ff_idctdsp_init
 * @id cpp/ffmpeg/b3332a182f8ba33a34542e4a0370f38b914ccf7d/ff-idctdsp-init
 * @description ffmpeg-b3332a182f8ba33a34542e4a0370f38b914ccf7d-libavcodec/idctdsp.c-ff_idctdsp_init CVE-2018-12460
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vavctx_238, PointerFieldAccess target_0) {
		target_0.getTarget().getName()="profile"
		and target_0.getQualifier().(VariableAccess).getTarget()=vavctx_238
}

predicate func_2(Parameter vavctx_238, ExprStmt target_3, LogicalAndExpr target_2) {
		target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="codec_id"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_238
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="profile"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_238
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="14"
		and target_2.getParent().(IfStmt).getThen()=target_3
}

predicate func_3(ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="idct_put"
}

from Function func, Parameter vavctx_238, PointerFieldAccess target_0, LogicalAndExpr target_2, ExprStmt target_3
where
func_0(vavctx_238, target_0)
and func_2(vavctx_238, target_3, target_2)
and func_3(target_3)
and vavctx_238.getType().hasName("AVCodecContext *")
and vavctx_238.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
