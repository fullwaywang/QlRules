/**
 * @name ffmpeg-6b5d3fb26fb4be48e4966e4b1d97c2165538d4ef-vp8_lossy_decode_frame
 * @id cpp/ffmpeg/6b5d3fb26fb4be48e4966e4b1d97c2165538d4ef/vp8-lossy-decode-frame
 * @description ffmpeg-6b5d3fb26fb4be48e4966e4b1d97c2165538d4ef-libavcodec/webp.c-vp8_lossy_decode_frame CVE-2017-9994
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vs_1330, Parameter vavctx_1326, IfStmt target_3, ExprStmt target_4) {
	exists(ConditionalExpr target_0 |
		target_0.getCondition().(PointerFieldAccess).getTarget().getName()="has_alpha"
		and target_0.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1330
		and target_0.getThen() instanceof EnumConstantAccess
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_0.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="pix_fmt"
		and target_0.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_1326
		and target_3.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vs_1330, ExprStmt target_5, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="has_alpha"
		and target_1.getQualifier().(VariableAccess).getTarget()=vs_1330
		and target_1.getParent().(IfStmt).getThen()=target_5
}

predicate func_3(Variable vs_1330, Parameter vavctx_1326, NotExpr target_6, IfStmt target_3) {
		target_3.getCondition().(PointerFieldAccess).getTarget().getName()="has_alpha"
		and target_3.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1330
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="pix_fmt"
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_1326
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof EnumConstantAccess
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
}

predicate func_4(Variable vs_1330, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="lossless"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1330
		and target_4.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_5(Parameter vavctx_1326, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="pix_fmt"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_1326
		and target_5.getExpr().(AssignExpr).getRValue() instanceof EnumConstantAccess
}

predicate func_6(Variable vs_1330, NotExpr target_6) {
		target_6.getOperand().(PointerFieldAccess).getTarget().getName()="initialized"
		and target_6.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1330
}

from Function func, Variable vs_1330, Parameter vavctx_1326, PointerFieldAccess target_1, IfStmt target_3, ExprStmt target_4, ExprStmt target_5, NotExpr target_6
where
not func_0(vs_1330, vavctx_1326, target_3, target_4)
and func_1(vs_1330, target_5, target_1)
and func_3(vs_1330, vavctx_1326, target_6, target_3)
and func_4(vs_1330, target_4)
and func_5(vavctx_1326, target_5)
and func_6(vs_1330, target_6)
and vs_1330.getType().hasName("WebPContext *")
and vavctx_1326.getType().hasName("AVCodecContext *")
and vs_1330.getParentScope+() = func
and vavctx_1326.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
