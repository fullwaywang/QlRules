/**
 * @name ffmpeg-14db3af4f26dad8e6ddf2147e96ccc710952ad4d-qdm2_fft_decode_tones
 * @id cpp/ffmpeg/14db3af4f26dad8e6ddf2147e96ccc710952ad4d/qdm2-fft-decode-tones
 * @description ffmpeg-14db3af4f26dad8e6ddf2147e96ccc710952ad4d-libavcodec/qdm2.c-qdm2_fft_decode_tones CVE-2011-4351
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="1"
		and not target_0.getValue()="0"
		and target_0.getParent().(WhileStmt).getParent().(BlockStmt).getStmt(10).(WhileStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="superblocktype_2_3"
		and target_0.getParent().(WhileStmt).getParent().(BlockStmt).getStmt(10).(WhileStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("QDM2Context *")
		and target_0.getParent().(WhileStmt).getParent().(BlockStmt).getStmt(10).(WhileStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_0.getParent().(WhileStmt).getParent().(BlockStmt).getStmt(10).(WhileStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="group_size"
		and target_0.getParent().(WhileStmt).getParent().(BlockStmt).getStmt(10).(WhileStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("QDM2Context *")
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Parameter vgb_1318, RelationalOperation target_3) {
	exists(RelationalOperation target_1 |
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getGreaterOperand().(FunctionCall).getTarget().hasName("get_bits_left")
		and target_1.getGreaterOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vgb_1318
		and target_1.getLesserOperand().(Literal).getValue()="0"
		and target_1.getGreaterOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_3(Parameter vgb_1318, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getLesserOperand().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_3.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("qdm2_get_vlc")
		and target_3.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vgb_1318
		and target_3.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType() instanceof ArrayType
		and target_3.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
		and target_3.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="1"
		and target_3.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="2"
		and target_3.getGreaterOperand().(Literal).getValue()="2"
}

from Function func, Parameter vgb_1318, Literal target_0, RelationalOperation target_3
where
func_0(func, target_0)
and not func_1(vgb_1318, target_3)
and func_3(vgb_1318, target_3)
and vgb_1318.getType().hasName("GetBitContext *")
and vgb_1318.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
