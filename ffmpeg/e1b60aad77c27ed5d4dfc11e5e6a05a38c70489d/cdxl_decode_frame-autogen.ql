/**
 * @name ffmpeg-e1b60aad77c27ed5d4dfc11e5e6a05a38c70489d-cdxl_decode_frame
 * @id cpp/ffmpeg/e1b60aad77c27ed5d4dfc11e5e6a05a38c70489d/cdxl-decode-frame
 * @description ffmpeg-e1b60aad77c27ed5d4dfc11e5e6a05a38c70489d-libavcodec/cdxl.c-cdxl_decode_frame CVE-2017-9996
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vc_242, BlockStmt target_2, RelationalOperation target_3, LogicalAndExpr target_1) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof LogicalAndExpr
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="format"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_242
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="32"
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vc_242, Variable vencoding_244, BlockStmt target_2, LogicalAndExpr target_1) {
		target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vencoding_244
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="palette_size"
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_242
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="bpp"
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_242
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="8"
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="pix_fmt"
}

predicate func_3(Variable vc_242, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getLesserOperand().(PointerFieldAccess).getTarget().getName()="video_size"
		and target_3.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_242
		and target_3.getGreaterOperand().(DivExpr).getLeftOperand().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_3.getGreaterOperand().(DivExpr).getLeftOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="bpp"
		and target_3.getGreaterOperand().(DivExpr).getLeftOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_242
		and target_3.getGreaterOperand().(DivExpr).getRightOperand().(Literal).getValue()="8"
}

from Function func, Variable vc_242, Variable vencoding_244, LogicalAndExpr target_1, BlockStmt target_2, RelationalOperation target_3
where
not func_0(vc_242, target_2, target_3, target_1)
and func_1(vc_242, vencoding_244, target_2, target_1)
and func_2(target_2)
and func_3(vc_242, target_3)
and vc_242.getType().hasName("CDXLVideoContext *")
and vencoding_244.getType().hasName("int")
and vc_242.getParentScope+() = func
and vencoding_244.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
