/**
 * @name ffmpeg-c42a1388a6d1bfd8001bf6a4241d8ca27e49326d-sdp_parse_fmtp_config_h264
 * @id cpp/ffmpeg/c42a1388a6d1bfd8001bf6a4241d8ca27e49326d/sdp-parse-fmtp-config-h264
 * @description ffmpeg-c42a1388a6d1bfd8001bf6a4241d8ca27e49326d-libavformat/rtpdec_h264.c-sdp_parse_fmtp_config_h264 CVE-2017-14767
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vvalue_147, BlockStmt target_2, ExprStmt target_3, EqualityOperation target_1) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vvalue_147
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vvalue_147, BlockStmt target_2, EqualityOperation target_1) {
		target_1.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vvalue_147
		and target_1.getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(FunctionCall).getTarget().hasName("strlen")
		and target_1.getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvalue_147
		and target_1.getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_1.getAnOperand().(CharLiteral).getValue()="44"
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="24"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Missing PPS in sprop-parameter-sets, ignoring\n"
		and target_2.getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
}

predicate func_3(Parameter vvalue_147, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("parse_profile_level_id")
		and target_3.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vvalue_147
}

from Function func, Parameter vvalue_147, EqualityOperation target_1, BlockStmt target_2, ExprStmt target_3
where
not func_0(vvalue_147, target_2, target_3, target_1)
and func_1(vvalue_147, target_2, target_1)
and func_2(target_2)
and func_3(vvalue_147, target_3)
and vvalue_147.getType().hasName("const char *")
and vvalue_147.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
