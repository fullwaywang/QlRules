/**
 * @name ffmpeg-7c32e9cf93b712f8463573a59ed4e98fd10fa013-ff_v4l2_m2m_codec_end
 * @id cpp/ffmpeg/7c32e9cf93b712f8463573a59ed4e98fd10fa013/ff-v4l2-m2m-codec-end
 * @description ffmpeg-7c32e9cf93b712f8463573a59ed4e98fd10fa013-libavcodec/v4l2_m2m.c-ff_v4l2_m2m_codec_end CVE-2020-22038
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vs_339, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vs_339
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_0))
}

predicate func_1(Variable vs_339, AddressOfExpr target_6, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="fd"
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_339
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_1.getThen().(BlockStmt).getStmt(1) instanceof IfStmt
		and target_1.getThen().(BlockStmt).getStmt(2) instanceof ExprStmt
		and target_1.getThen().(BlockStmt).getStmt(3) instanceof IfStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_1)
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vs_339, Variable vret_340, Function func, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_340
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ff_v4l2_context_set_status")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="output"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_339
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(BitwiseOrExpr).getValue()="1074026003"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

predicate func_3(Variable vs_339, Variable vret_340, Function func, IfStmt target_3) {
		target_3.getCondition().(VariableAccess).getTarget()=vret_340
		and target_3.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_3.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="avctx"
		and target_3.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_339
		and target_3.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_3.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="VIDIOC_STREAMOFF %s\n"
		and target_3.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getTarget().getName()="name"
		and target_3.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="output"
		and target_3.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_339
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3
}

predicate func_4(Variable vs_339, Variable vret_340, Function func, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_340
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ff_v4l2_context_set_status")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="capture"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_339
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(BitwiseOrExpr).getValue()="1074026003"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4
}

predicate func_5(Variable vs_339, Variable vret_340, Function func, IfStmt target_5) {
		target_5.getCondition().(VariableAccess).getTarget()=vret_340
		and target_5.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_5.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="avctx"
		and target_5.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_339
		and target_5.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_5.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="VIDIOC_STREAMOFF %s\n"
		and target_5.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getTarget().getName()="name"
		and target_5.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="capture"
		and target_5.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_339
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_5
}

predicate func_6(Variable vs_339, AddressOfExpr target_6) {
		target_6.getOperand().(PointerFieldAccess).getTarget().getName()="output"
		and target_6.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_339
}

from Function func, Variable vs_339, Variable vret_340, ExprStmt target_2, IfStmt target_3, ExprStmt target_4, IfStmt target_5, AddressOfExpr target_6
where
not func_0(vs_339, func)
and not func_1(vs_339, target_6, func)
and func_2(vs_339, vret_340, func, target_2)
and func_3(vs_339, vret_340, func, target_3)
and func_4(vs_339, vret_340, func, target_4)
and func_5(vs_339, vret_340, func, target_5)
and func_6(vs_339, target_6)
and vs_339.getType().hasName("V4L2m2mContext *")
and vret_340.getType().hasName("int")
and vs_339.getParentScope+() = func
and vret_340.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
