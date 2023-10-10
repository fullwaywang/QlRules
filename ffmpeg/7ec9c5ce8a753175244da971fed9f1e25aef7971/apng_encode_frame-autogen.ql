/**
 * @name ffmpeg-7ec9c5ce8a753175244da971fed9f1e25aef7971-apng_encode_frame
 * @id cpp/ffmpeg/7ec9c5ce8a753175244da971fed9f1e25aef7971/apng-encode-frame
 * @description ffmpeg-7ec9c5ce8a753175244da971fed9f1e25aef7971-libavcodec/pngenc.c-apng_encode_frame CVE-2016-2327
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vs_712, Variable vdiffFrame_715, MulExpr target_9, RelationalOperation target_10) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("av_frame_copy")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vdiffFrame_715
		and target_0.getArgument(1).(PointerFieldAccess).getTarget().getName()="last_frame"
		and target_0.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_712
		and target_0.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getRightOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getArgument(0).(VariableAccess).getLocation().isBefore(target_10.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vs_712, Variable vdiffFrame_715, NotExpr target_11, MulExpr target_12, PointerArithmeticOperation target_13, ArrayExpr target_14) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("av_frame_copy")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vdiffFrame_715
		and target_1.getArgument(1).(PointerFieldAccess).getTarget().getName()="prev_frame"
		and target_1.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_712
		and target_11.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_12.getRightOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_13.getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getArgument(0).(VariableAccess).getLocation())
		and target_1.getArgument(0).(VariableAccess).getLocation().isBefore(target_14.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vdiffFrame_715, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="data"
		and target_2.getQualifier().(VariableAccess).getTarget()=vdiffFrame_715
		and target_2.getParent().(ArrayExpr).getArrayOffset() instanceof Literal
}

predicate func_3(Variable vs_712, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="linesize"
		and target_3.getQualifier().(PointerFieldAccess).getTarget().getName()="last_frame"
		and target_3.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_712
		and target_3.getParent().(ArrayExpr).getArrayOffset() instanceof Literal
}

predicate func_4(Variable vs_712, PointerFieldAccess target_4) {
		target_4.getTarget().getName()="last_frame"
		and target_4.getQualifier().(VariableAccess).getTarget()=vs_712
}

predicate func_5(Variable vs_712, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="prev_frame"
		and target_5.getQualifier().(VariableAccess).getTarget()=vs_712
}

predicate func_6(Variable vdiffFrame_715, VariableAccess target_6) {
		target_6.getTarget()=vdiffFrame_715
}

predicate func_7(Variable vs_712, Variable vdiffFrame_715, FunctionCall target_7) {
		target_7.getTarget().hasName("memcpy")
		and target_7.getArgument(0).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_7.getArgument(0).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdiffFrame_715
		and target_7.getArgument(0).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_7.getArgument(1).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_7.getArgument(1).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="last_frame"
		and target_7.getArgument(1).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_712
		and target_7.getArgument(1).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_7.getArgument(2).(MulExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="linesize"
		and target_7.getArgument(2).(MulExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="last_frame"
		and target_7.getArgument(2).(MulExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_712
		and target_7.getArgument(2).(MulExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_7.getArgument(2).(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_7.getArgument(2).(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="last_frame"
		and target_7.getArgument(2).(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_712
}

predicate func_8(Variable vs_712, Variable vdiffFrame_715, FunctionCall target_8) {
		target_8.getTarget().hasName("memcpy")
		and target_8.getArgument(0).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_8.getArgument(0).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdiffFrame_715
		and target_8.getArgument(0).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_8.getArgument(1).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_8.getArgument(1).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="prev_frame"
		and target_8.getArgument(1).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_712
		and target_8.getArgument(1).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_8.getArgument(2).(MulExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="linesize"
		and target_8.getArgument(2).(MulExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="prev_frame"
		and target_8.getArgument(2).(MulExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_712
		and target_8.getArgument(2).(MulExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_8.getArgument(2).(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_8.getArgument(2).(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="prev_frame"
		and target_8.getArgument(2).(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_712
}

predicate func_9(Variable vs_712, MulExpr target_9) {
		target_9.getLeftOperand() instanceof ArrayExpr
		and target_9.getRightOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_9.getRightOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="last_frame"
		and target_9.getRightOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_712
}

predicate func_10(Variable vdiffFrame_715, RelationalOperation target_10) {
		 (target_10 instanceof GTExpr or target_10 instanceof LTExpr)
		and target_10.getLesserOperand().(FunctionCall).getTarget().hasName("apng_do_inverse_blend")
		and target_10.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdiffFrame_715
		and target_10.getGreaterOperand().(Literal).getValue()="0"
}

predicate func_11(Variable vs_712, NotExpr target_11) {
		target_11.getOperand().(PointerFieldAccess).getTarget().getName()="prev_frame"
		and target_11.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_712
}

predicate func_12(Variable vs_712, MulExpr target_12) {
		target_12.getLeftOperand() instanceof ArrayExpr
		and target_12.getRightOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_12.getRightOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="prev_frame"
		and target_12.getRightOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_712
}

predicate func_13(Variable vdiffFrame_715, PointerArithmeticOperation target_13) {
		target_13.getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_13.getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdiffFrame_715
		and target_13.getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

predicate func_14(Variable vdiffFrame_715, ArrayExpr target_14) {
		target_14.getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_14.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdiffFrame_715
		and target_14.getArrayOffset() instanceof Literal
}

from Function func, Variable vs_712, Variable vdiffFrame_715, PointerFieldAccess target_2, PointerFieldAccess target_3, PointerFieldAccess target_4, PointerFieldAccess target_5, VariableAccess target_6, FunctionCall target_7, FunctionCall target_8, MulExpr target_9, RelationalOperation target_10, NotExpr target_11, MulExpr target_12, PointerArithmeticOperation target_13, ArrayExpr target_14
where
not func_0(vs_712, vdiffFrame_715, target_9, target_10)
and not func_1(vs_712, vdiffFrame_715, target_11, target_12, target_13, target_14)
and func_2(vdiffFrame_715, target_2)
and func_3(vs_712, target_3)
and func_4(vs_712, target_4)
and func_5(vs_712, target_5)
and func_6(vdiffFrame_715, target_6)
and func_7(vs_712, vdiffFrame_715, target_7)
and func_8(vs_712, vdiffFrame_715, target_8)
and func_9(vs_712, target_9)
and func_10(vdiffFrame_715, target_10)
and func_11(vs_712, target_11)
and func_12(vs_712, target_12)
and func_13(vdiffFrame_715, target_13)
and func_14(vdiffFrame_715, target_14)
and vs_712.getType().hasName("PNGEncContext *")
and vdiffFrame_715.getType().hasName("AVFrame *")
and vs_712.getParentScope+() = func
and vdiffFrame_715.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
