/**
 * @name ffmpeg-7ec9c5ce8a753175244da971fed9f1e25aef7971-encode_apng
 * @id cpp/ffmpeg/7ec9c5ce8a753175244da971fed9f1e25aef7971/encode-apng
 * @description ffmpeg-7ec9c5ce8a753175244da971fed9f1e25aef7971-libavcodec/pngenc.c-encode_apng CVE-2016-2327
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vs_835, EqualityOperation target_6, PointerFieldAccess target_0) {
		target_0.getTarget().getName()="last_frame"
		and target_0.getQualifier().(VariableAccess).getTarget()=vs_835
		and target_0.getQualifier().(VariableAccess).getLocation().isBefore(target_6.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_1(Variable vs_835, MulExpr target_7) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("av_frame_copy")
		and target_1.getArgument(0).(PointerFieldAccess).getTarget().getName()="prev_frame"
		and target_1.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_835
		and target_1.getArgument(1).(PointerFieldAccess).getTarget().getName()="last_frame"
		and target_1.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_835
		and target_7.getRightOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vs_835, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="data"
		and target_2.getQualifier().(PointerFieldAccess).getTarget().getName()="prev_frame"
		and target_2.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_835
		and target_2.getParent().(ArrayExpr).getArrayOffset() instanceof Literal
}

predicate func_3(Variable vs_835, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="linesize"
		and target_3.getQualifier().(PointerFieldAccess).getTarget().getName()="last_frame"
		and target_3.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_835
		and target_3.getParent().(ArrayExpr).getArrayOffset() instanceof Literal
}

predicate func_4(Variable vs_835, PointerFieldAccess target_4) {
		target_4.getTarget().getName()="last_frame"
		and target_4.getQualifier().(VariableAccess).getTarget()=vs_835
}

predicate func_5(Variable vs_835, FunctionCall target_5) {
		target_5.getTarget().hasName("memcpy")
		and target_5.getArgument(0).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_5.getArgument(0).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="prev_frame"
		and target_5.getArgument(0).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_835
		and target_5.getArgument(0).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_5.getArgument(1).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_5.getArgument(1).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="last_frame"
		and target_5.getArgument(1).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_835
		and target_5.getArgument(1).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_5.getArgument(2).(MulExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="linesize"
		and target_5.getArgument(2).(MulExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="last_frame"
		and target_5.getArgument(2).(MulExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_835
		and target_5.getArgument(2).(MulExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_5.getArgument(2).(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_5.getArgument(2).(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="last_frame"
		and target_5.getArgument(2).(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_835
}

predicate func_6(Variable vs_835, EqualityOperation target_6) {
		target_6.getAnOperand().(ValueFieldAccess).getTarget().getName()="dispose_op"
		and target_6.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="last_frame_fctl"
		and target_6.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_835
}

predicate func_7(Variable vs_835, MulExpr target_7) {
		target_7.getLeftOperand() instanceof ArrayExpr
		and target_7.getRightOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_7.getRightOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="last_frame"
		and target_7.getRightOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_835
}

from Function func, Variable vs_835, PointerFieldAccess target_0, PointerFieldAccess target_2, PointerFieldAccess target_3, PointerFieldAccess target_4, FunctionCall target_5, EqualityOperation target_6, MulExpr target_7
where
func_0(vs_835, target_6, target_0)
and not func_1(vs_835, target_7)
and func_2(vs_835, target_2)
and func_3(vs_835, target_3)
and func_4(vs_835, target_4)
and func_5(vs_835, target_5)
and func_6(vs_835, target_6)
and func_7(vs_835, target_7)
and vs_835.getType().hasName("PNGEncContext *")
and vs_835.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
