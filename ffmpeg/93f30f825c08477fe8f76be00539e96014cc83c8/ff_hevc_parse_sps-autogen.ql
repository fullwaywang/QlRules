/**
 * @name ffmpeg-93f30f825c08477fe8f76be00539e96014cc83c8-ff_hevc_parse_sps
 * @id cpp/ffmpeg/93f30f825c08477fe8f76be00539e96014cc83c8/ff-hevc-parse-sps
 * @description ffmpeg-93f30f825c08477fe8f76be00539e96014cc83c8-libavcodec/hevc_ps.c-ff_hevc_parse_sps CVE-2015-8217
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vavctx_797, Parameter vsps_796, ExprStmt target_1, RelationalOperation target_2, ExprStmt target_3, EqualityOperation target_4, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="chroma_format_idc"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsps_796
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="3"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_797
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="chroma_format_idc %d is invalid\n"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="chroma_format_idc"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsps_796
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1094995529"
		and (func.getEntryPoint().(BlockStmt).getStmt(14)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(14).getFollowingStmt()=target_0)
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getLocation())
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vavctx_797, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_797
		and target_1.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_1.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="SPS id out of range: %d\n"
}

predicate func_2(Parameter vavctx_797, Parameter vsps_796, RelationalOperation target_2) {
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_image_check_size")
		and target_2.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="width"
		and target_2.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsps_796
		and target_2.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="height"
		and target_2.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsps_796
		and target_2.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_2.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vavctx_797
		and target_2.getGreaterOperand().(Literal).getValue()="0"
}

predicate func_3(Parameter vsps_796, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="chroma_format_idc"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsps_796
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("get_ue_golomb_long")
}

predicate func_4(Parameter vsps_796, EqualityOperation target_4) {
		target_4.getAnOperand().(PointerFieldAccess).getTarget().getName()="chroma_format_idc"
		and target_4.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsps_796
		and target_4.getAnOperand().(Literal).getValue()="3"
}

from Function func, Parameter vavctx_797, Parameter vsps_796, ExprStmt target_1, RelationalOperation target_2, ExprStmt target_3, EqualityOperation target_4
where
not func_0(vavctx_797, vsps_796, target_1, target_2, target_3, target_4, func)
and func_1(vavctx_797, target_1)
and func_2(vavctx_797, vsps_796, target_2)
and func_3(vsps_796, target_3)
and func_4(vsps_796, target_4)
and vavctx_797.getType().hasName("AVCodecContext *")
and vsps_796.getType().hasName("HEVCSPS *")
and vavctx_797.getParentScope+() = func
and vsps_796.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
