/**
 * @name ffmpeg-4a80ebe491609e04110a1dd540a0ca79d3be3d04-allocate_frame_buffers
 * @id cpp/ffmpeg/4a80ebe491609e04110a1dd540a0ca79d3be3d04/allocate-frame-buffers
 * @description ffmpeg-4a80ebe491609e04110a1dd540a0ca79d3be3d04-libavcodec/indeo3.c-allocate_frame_buffers CVE-2012-2804
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vluma_width_153, Parameter vctx_150, LogicalOrExpr target_9) {
	exists(AssignExpr target_0 |
		target_0.getLValue().(PointerFieldAccess).getTarget().getName()="width"
		and target_0.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_150
		and target_0.getRValue().(VariableAccess).getTarget()=vluma_width_153
		and target_0.getRValue().(VariableAccess).getLocation().isBefore(target_9.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vluma_height_153, Parameter vctx_150, ArrayExpr target_12) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(PointerFieldAccess).getTarget().getName()="height"
		and target_1.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_150
		and target_1.getRValue().(VariableAccess).getTarget()=vluma_height_153
		and target_1.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_12.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vctx_150, VariableAccess target_2) {
		target_2.getTarget()=vctx_150
}

predicate func_3(Parameter vctx_150, VariableAccess target_3) {
		target_3.getTarget()=vctx_150
}

predicate func_6(Variable vluma_width_153, Parameter vctx_150, AssignExpr target_6) {
		target_6.getLValue().(VariableAccess).getTarget()=vluma_width_153
		and target_6.getRValue().(PointerFieldAccess).getTarget().getName()="width"
		and target_6.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_150
}

predicate func_7(Variable vluma_height_153, Parameter vctx_150, AssignExpr target_7) {
		target_7.getLValue().(VariableAccess).getTarget()=vluma_height_153
		and target_7.getRValue().(PointerFieldAccess).getTarget().getName()="height"
		and target_7.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_150
}

predicate func_9(Variable vluma_width_153, Variable vluma_height_153, LogicalOrExpr target_9) {
		target_9.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vluma_width_153
		and target_9.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="16"
		and target_9.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vluma_width_153
		and target_9.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="640"
		and target_9.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vluma_height_153
		and target_9.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="16"
		and target_9.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vluma_height_153
		and target_9.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="480"
		and target_9.getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vluma_width_153
		and target_9.getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="3"
		and target_9.getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vluma_height_153
		and target_9.getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="3"
}

predicate func_12(Parameter vctx_150, ArrayExpr target_12) {
		target_12.getArrayBase().(PointerFieldAccess).getTarget().getName()="planes"
		and target_12.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_150
		and target_12.getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
}

from Function func, Variable vluma_width_153, Variable vluma_height_153, Parameter vctx_150, VariableAccess target_2, VariableAccess target_3, AssignExpr target_6, AssignExpr target_7, LogicalOrExpr target_9, ArrayExpr target_12
where
not func_0(vluma_width_153, vctx_150, target_9)
and not func_1(vluma_height_153, vctx_150, target_12)
and func_2(vctx_150, target_2)
and func_3(vctx_150, target_3)
and func_6(vluma_width_153, vctx_150, target_6)
and func_7(vluma_height_153, vctx_150, target_7)
and func_9(vluma_width_153, vluma_height_153, target_9)
and func_12(vctx_150, target_12)
and vluma_width_153.getType().hasName("int")
and vluma_height_153.getType().hasName("int")
and vctx_150.getType().hasName("Indeo3DecodeContext *")
and vluma_width_153.(LocalVariable).getFunction() = func
and vluma_height_153.(LocalVariable).getFunction() = func
and vctx_150.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
