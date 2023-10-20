/**
 * @name ffmpeg-ea38e5a6b75706477898eb1e6582d667dbb9946c-ff_hevc_decode_nal_sps
 * @id cpp/ffmpeg/ea38e5a6b75706477898eb1e6582d667dbb9946c/ff-hevc-decode-nal-sps
 * @description ffmpeg-ea38e5a6b75706477898eb1e6582d667dbb9946c-libavcodec/hevc_ps.c-ff_hevc_decode_nal_sps CVE-2014-9319
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vsps_712, PointerFieldAccess target_1, ExprStmt target_2, RelationalOperation target_3) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="num_long_term_ref_pics_sps"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsps_712
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="31"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="num_long_term_ref_pics_sps %d is out of range.\n"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="num_long_term_ref_pics_sps"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsps_712
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vsps_712, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="long_term_ref_pics_present_flag"
		and target_1.getQualifier().(VariableAccess).getTarget()=vsps_712
}

predicate func_2(Variable vsps_712, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="num_long_term_ref_pics_sps"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsps_712
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("get_ue_golomb_long")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("GetBitContext *")
}

predicate func_3(Variable vsps_712, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getLesserOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_3.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="num_long_term_ref_pics_sps"
		and target_3.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsps_712
}

from Function func, Variable vsps_712, PointerFieldAccess target_1, ExprStmt target_2, RelationalOperation target_3
where
not func_0(vsps_712, target_1, target_2, target_3)
and func_1(vsps_712, target_1)
and func_2(vsps_712, target_2)
and func_3(vsps_712, target_3)
and vsps_712.getType().hasName("HEVCSPS *")
and vsps_712.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
