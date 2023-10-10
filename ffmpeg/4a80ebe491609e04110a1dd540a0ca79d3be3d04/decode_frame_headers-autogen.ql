/**
 * @name ffmpeg-4a80ebe491609e04110a1dd540a0ca79d3be3d04-decode_frame_headers
 * @id cpp/ffmpeg/4a80ebe491609e04110a1dd540a0ca79d3be3d04/decode-frame-headers
 * @description ffmpeg-4a80ebe491609e04110a1dd540a0ca79d3be3d04-libavcodec/indeo3.c-decode_frame_headers CVE-2012-2804
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vwidth_885, Parameter vctx_879, VariableAccess target_0) {
		target_0.getTarget()=vwidth_885
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_0.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="width"
		and target_0.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_879
}

predicate func_1(Variable vheight_885, Parameter vctx_879, VariableAccess target_1) {
		target_1.getTarget()=vheight_885
		and target_1.getParent().(AssignExpr).getRValue() = target_1
		and target_1.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="height"
		and target_1.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_879
}

predicate func_2(Variable vwidth_885, Parameter vctx_879, LogicalOrExpr target_4, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="width"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_879
		and target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vwidth_885
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
}

predicate func_3(Variable vheight_885, Parameter vctx_879, LogicalOrExpr target_4, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="height"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_879
		and target_3.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vheight_885
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
}

predicate func_4(Variable vheight_885, Variable vwidth_885, Parameter vctx_879, LogicalOrExpr target_4) {
		target_4.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vwidth_885
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_879
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vheight_885
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_879
}

from Function func, Variable vheight_885, Variable vwidth_885, Parameter vctx_879, VariableAccess target_0, VariableAccess target_1, ExprStmt target_2, ExprStmt target_3, LogicalOrExpr target_4
where
func_0(vwidth_885, vctx_879, target_0)
and func_1(vheight_885, vctx_879, target_1)
and func_2(vwidth_885, vctx_879, target_4, target_2)
and func_3(vheight_885, vctx_879, target_4, target_3)
and func_4(vheight_885, vwidth_885, vctx_879, target_4)
and vheight_885.getType().hasName("uint16_t")
and vwidth_885.getType().hasName("uint16_t")
and vctx_879.getType().hasName("Indeo3DecodeContext *")
and vheight_885.(LocalVariable).getFunction() = func
and vwidth_885.(LocalVariable).getFunction() = func
and vctx_879.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
