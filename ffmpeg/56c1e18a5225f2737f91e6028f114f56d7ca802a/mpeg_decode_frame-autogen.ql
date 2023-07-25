/**
 * @name ffmpeg-56c1e18a5225f2737f91e6028f114f56d7ca802a-mpeg_decode_frame
 * @id cpp/ffmpeg/56c1e18a5225f2737f91e6028f114f56d7ca802a/mpeg-decode-frame
 * @description ffmpeg-56c1e18a5225f2737f91e6028f114f56d7ca802a-libavcodec/mpeg12.c-mpeg_decode_frame CVE-2012-2803
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vavctx_2192, PointerFieldAccess target_0) {
		target_0.getTarget().getName()="frame_number"
		and target_0.getQualifier().(VariableAccess).getTarget()=vavctx_2192
}

predicate func_2(Variable vs_2198, LogicalAndExpr target_3) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="extradata_decoded"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_2198
		and target_2.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3)
}

predicate func_3(Parameter vavctx_2192, LogicalAndExpr target_3) {
		target_3.getAnOperand().(PointerFieldAccess).getTarget().getName()="extradata"
		and target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_2192
		and target_3.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="frame_number"
		and target_3.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_2192
}

from Function func, Parameter vavctx_2192, Variable vs_2198, PointerFieldAccess target_0, LogicalAndExpr target_3
where
func_0(vavctx_2192, target_0)
and not func_2(vs_2198, target_3)
and func_3(vavctx_2192, target_3)
and vavctx_2192.getType().hasName("AVCodecContext *")
and vs_2198.getType().hasName("Mpeg1Context *")
and vavctx_2192.getFunction() = func
and vs_2198.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
