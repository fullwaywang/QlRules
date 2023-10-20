/**
 * @name ffmpeg-229e4c133287955d5f3f837520a3602709b21950-decode_pic_hdr
 * @id cpp/ffmpeg/229e4c133287955d5f3f837520a3602709b21950/decode-pic-hdr
 * @description ffmpeg-229e4c133287955d5f3f837520a3602709b21950-libavcodec/indeo5.c-decode_pic_hdr CVE-2012-2779
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctx_322, EqualityOperation target_2, FunctionCall target_3) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="gop_invalid"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_322
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vctx_322, EqualityOperation target_2, FunctionCall target_3, EqualityOperation target_4) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="gop_invalid"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_322
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_3.getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vctx_322, EqualityOperation target_2) {
		target_2.getAnOperand().(PointerFieldAccess).getTarget().getName()="frame_type"
		and target_2.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_322
}

predicate func_3(Parameter vctx_322, FunctionCall target_3) {
		target_3.getTarget().hasName("decode_gop_header")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vctx_322
		and target_3.getArgument(1).(VariableAccess).getTarget().getType().hasName("AVCodecContext *")
}

predicate func_4(Parameter vctx_322, EqualityOperation target_4) {
		target_4.getAnOperand().(PointerFieldAccess).getTarget().getName()="frame_type"
		and target_4.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_322
}

from Function func, Parameter vctx_322, EqualityOperation target_2, FunctionCall target_3, EqualityOperation target_4
where
not func_0(vctx_322, target_2, target_3)
and not func_1(vctx_322, target_2, target_3, target_4)
and func_2(vctx_322, target_2)
and func_3(vctx_322, target_3)
and func_4(vctx_322, target_4)
and vctx_322.getType().hasName("IVI5DecContext *")
and vctx_322.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
