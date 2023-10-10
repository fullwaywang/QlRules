/**
 * @name ffmpeg-291d74a46d32183653db07818c7b3407fd50a288-qdm2_decode_init
 * @id cpp/ffmpeg/291d74a46d32183653db07818c7b3407fd50a288/qdm2-decode-init
 * @description ffmpeg-291d74a46d32183653db07818c7b3407fd50a288-libavcodec/qdm2.c-qdm2_decode_init CVE-2011-4351
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vs_1708, ExprStmt target_2, ExprStmt target_3, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="channels"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1708
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="2"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1094995529"
		and (func.getEntryPoint().(BlockStmt).getStmt(21)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(21).getFollowingStmt()=target_0)
		and target_2.getExpr().(AssignExpr).getRValue().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vs_1708, ExprStmt target_4, ExprStmt target_5, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="frame_size"
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1708
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="512"
		and target_1.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1094995529"
		and (func.getEntryPoint().(BlockStmt).getStmt(35)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(35).getFollowingStmt()=target_1)
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vs_1708, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="channels"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("AVCodecContext *")
		and target_2.getExpr().(AssignExpr).getRValue().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="nb_channels"
		and target_2.getExpr().(AssignExpr).getRValue().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1708
		and target_2.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="channels"
		and target_2.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1708
		and target_2.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_bswap32")
		and target_2.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="l"
		and target_2.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("uint8_t *")
}

predicate func_3(Variable vs_1708, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="group_size"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1708
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_bswap32")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="l"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("uint8_t *")
}

predicate func_4(Variable vs_1708, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="frame_size"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1708
		and target_4.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="group_size"
		and target_4.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1708
		and target_4.getExpr().(AssignExpr).getRValue().(DivExpr).getRightOperand().(Literal).getValue()="16"
}

predicate func_5(Variable vs_1708, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="sub_sampling"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1708
		and target_5.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="fft_order"
		and target_5.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1708
		and target_5.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="7"
}

from Function func, Variable vs_1708, ExprStmt target_2, ExprStmt target_3, ExprStmt target_4, ExprStmt target_5
where
not func_0(vs_1708, target_2, target_3, func)
and not func_1(vs_1708, target_4, target_5, func)
and func_2(vs_1708, target_2)
and func_3(vs_1708, target_3)
and func_4(vs_1708, target_4)
and func_5(vs_1708, target_5)
and vs_1708.getType().hasName("QDM2Context *")
and vs_1708.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
