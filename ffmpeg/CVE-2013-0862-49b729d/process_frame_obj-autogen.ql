/**
 * @name ffmpeg-49b729d3af8464de431362e6c5b3027102bc2f88-process_frame_obj
 * @id cpp/ffmpeg/49b729d3af8464de431362e6c5b3027102bc2f88/process-frame-obj
 * @description ffmpeg-49b729d3af8464de431362e6c5b3027102bc2f88-libavcodec/sanm.c-process_frame_obj CVE-2013-0862
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctx_708, LogicalOrExpr target_8) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("av_image_check_size")
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0) instanceof ConditionalExpr
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(1) instanceof ConditionalExpr
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="avctx"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_708
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1094995529"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8)
}

predicate func_1(Parameter vctx_708, Variable vtop_710, Variable vleft_710, Variable vw_710, Variable vh_710, LogicalOrExpr target_8, ExprStmt target_7) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("avcodec_set_dimensions")
		and target_1.getArgument(0).(PointerFieldAccess).getTarget().getName()="avctx"
		and target_1.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_708
		and target_1.getArgument(1).(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vleft_710
		and target_1.getArgument(1).(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vw_710
		and target_1.getArgument(1).(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_1.getArgument(1).(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_708
		and target_1.getArgument(1).(ConditionalExpr).getThen().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vleft_710
		and target_1.getArgument(1).(ConditionalExpr).getThen().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vw_710
		and target_1.getArgument(1).(ConditionalExpr).getElse().(PointerFieldAccess).getTarget().getName()="width"
		and target_1.getArgument(1).(ConditionalExpr).getElse().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_708
		and target_1.getArgument(2).(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vtop_710
		and target_1.getArgument(2).(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vh_710
		and target_1.getArgument(2).(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_1.getArgument(2).(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_708
		and target_1.getArgument(2).(ConditionalExpr).getThen().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vtop_710
		and target_1.getArgument(2).(ConditionalExpr).getThen().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vh_710
		and target_1.getArgument(2).(ConditionalExpr).getElse().(PointerFieldAccess).getTarget().getName()="height"
		and target_1.getArgument(2).(ConditionalExpr).getElse().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_708
		and target_8.getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getArgument(2).(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation()))
}

/*predicate func_2(Parameter vctx_708, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="avctx"
		and target_2.getQualifier().(VariableAccess).getTarget()=vctx_708
}

*/
predicate func_3(Parameter vctx_708, Variable vleft_710, Variable vw_710, ConditionalExpr target_3) {
		target_3.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vleft_710
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vw_710
		and target_3.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_3.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_708
		and target_3.getThen().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vleft_710
		and target_3.getThen().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vw_710
		and target_3.getElse().(PointerFieldAccess).getTarget().getName()="width"
		and target_3.getElse().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_708
		and target_3.getParent().(AssignExpr).getRValue() = target_3
		and target_3.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="width"
		and target_3.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="avctx"
		and target_3.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_708
}

/*predicate func_4(Parameter vctx_708, PointerFieldAccess target_4) {
		target_4.getTarget().getName()="avctx"
		and target_4.getQualifier().(VariableAccess).getTarget()=vctx_708
}

*/
predicate func_5(Parameter vctx_708, Variable vtop_710, Variable vh_710, ConditionalExpr target_5) {
		target_5.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vtop_710
		and target_5.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vh_710
		and target_5.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_5.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_708
		and target_5.getThen().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vtop_710
		and target_5.getThen().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vh_710
		and target_5.getElse().(PointerFieldAccess).getTarget().getName()="height"
		and target_5.getElse().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_708
		and target_5.getParent().(AssignExpr).getRValue() = target_5
		and target_5.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="height"
		and target_5.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="avctx"
		and target_5.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_708
}

predicate func_6(Parameter vctx_708, AssignExpr target_6) {
		target_6.getLValue().(PointerFieldAccess).getTarget().getName()="width"
		and target_6.getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="avctx"
		and target_6.getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_708
		and target_6.getRValue() instanceof ConditionalExpr
}

predicate func_7(Parameter vctx_708, LogicalOrExpr target_8, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="height"
		and target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="avctx"
		and target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_708
		and target_7.getExpr().(AssignExpr).getRValue() instanceof ConditionalExpr
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
}

predicate func_8(Parameter vctx_708, Variable vtop_710, Variable vleft_710, Variable vw_710, Variable vh_710, LogicalOrExpr target_8) {
		target_8.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_8.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_708
		and target_8.getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vleft_710
		and target_8.getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vw_710
		and target_8.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_8.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_708
		and target_8.getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vtop_710
		and target_8.getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vh_710
}

from Function func, Parameter vctx_708, Variable vtop_710, Variable vleft_710, Variable vw_710, Variable vh_710, ConditionalExpr target_3, ConditionalExpr target_5, AssignExpr target_6, ExprStmt target_7, LogicalOrExpr target_8
where
not func_0(vctx_708, target_8)
and not func_1(vctx_708, vtop_710, vleft_710, vw_710, vh_710, target_8, target_7)
and func_3(vctx_708, vleft_710, vw_710, target_3)
and func_5(vctx_708, vtop_710, vh_710, target_5)
and func_6(vctx_708, target_6)
and func_7(vctx_708, target_8, target_7)
and func_8(vctx_708, vtop_710, vleft_710, vw_710, vh_710, target_8)
and vctx_708.getType().hasName("SANMVideoContext *")
and vtop_710.getType().hasName("uint16_t")
and vleft_710.getType().hasName("uint16_t")
and vw_710.getType().hasName("uint16_t")
and vh_710.getType().hasName("uint16_t")
and vctx_708.getFunction() = func
and vtop_710.(LocalVariable).getFunction() = func
and vleft_710.(LocalVariable).getFunction() = func
and vw_710.(LocalVariable).getFunction() = func
and vh_710.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
