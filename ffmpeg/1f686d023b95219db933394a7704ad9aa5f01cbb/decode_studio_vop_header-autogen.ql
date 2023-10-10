/**
 * @name ffmpeg-1f686d023b95219db933394a7704ad9aa5f01cbb-decode_studio_vop_header
 * @id cpp/ffmpeg/1f686d023b95219db933394a7704ad9aa5f01cbb/decode-studio-vop-header
 * @description ffmpeg-1f686d023b95219db933394a7704ad9aa5f01cbb-libavcodec/mpeg4videodec.c-decode_studio_vop_header CVE-2019-11339
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vs_3054, ExprStmt target_1, ExprStmt target_2, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="interlaced_dct"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_3054
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vs_3054, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="partitioned_frame"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_3054
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_2(Variable vs_3054, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="decode_mb"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_3054
}

from Function func, Variable vs_3054, ExprStmt target_1, ExprStmt target_2
where
not func_0(vs_3054, target_1, target_2, func)
and func_1(vs_3054, target_1)
and func_2(vs_3054, target_2)
and vs_3054.getType().hasName("MpegEncContext *")
and vs_3054.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
