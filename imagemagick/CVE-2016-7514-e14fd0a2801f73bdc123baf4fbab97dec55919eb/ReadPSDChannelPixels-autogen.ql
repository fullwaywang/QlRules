/**
 * @name imagemagick-e14fd0a2801f73bdc123baf4fbab97dec55919eb-ReadPSDChannelPixels
 * @id cpp/imagemagick/e14fd0a2801f73bdc123baf4fbab97dec55919eb/ReadPSDChannelPixels
 * @description imagemagick-e14fd0a2801f73bdc123baf4fbab97dec55919eb-coders/psd.c-ReadPSDChannelPixels CVE-2016-7514
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vimage_767, Parameter vexception_769, PointerArithmeticOperation target_2, PointerArithmeticOperation target_3, FunctionCall target_4) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("ConstrainColormapIndex")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vimage_767
		and target_0.getArgument(1) instanceof FunctionCall
		and target_0.getArgument(2).(VariableAccess).getTarget()=vexception_769
		and target_2.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getArgument(0).(VariableAccess).getLocation())
		and target_3.getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_0.getArgument(2).(VariableAccess).getLocation())
		and target_0.getArgument(2).(VariableAccess).getLocation().isBefore(target_4.getArgument(1).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vimage_767, Variable vq_778, FunctionCall target_1) {
		target_1.getTarget().hasName("GetPixelIndex")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vimage_767
		and target_1.getArgument(1).(VariableAccess).getTarget()=vq_778
}

predicate func_2(Parameter vimage_767, PointerArithmeticOperation target_2) {
		target_2.getAnOperand().(PointerFieldAccess).getTarget().getName()="colormap"
		and target_2.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_767
		and target_2.getAnOperand() instanceof FunctionCall
}

predicate func_3(Parameter vimage_767, Parameter vexception_769, Variable vq_778, PointerArithmeticOperation target_3) {
		target_3.getAnOperand().(PointerFieldAccess).getTarget().getName()="colormap"
		and target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_767
		and target_3.getAnOperand().(FunctionCall).getTarget().hasName("ConstrainColormapIndex")
		and target_3.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_767
		and target_3.getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("GetPixelIndex")
		and target_3.getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_767
		and target_3.getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vq_778
		and target_3.getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vexception_769
}

predicate func_4(Parameter vimage_767, Parameter vexception_769, FunctionCall target_4) {
		target_4.getTarget().hasName("SyncAuthenticPixels")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vimage_767
		and target_4.getArgument(1).(VariableAccess).getTarget()=vexception_769
}

from Function func, Parameter vimage_767, Parameter vexception_769, Variable vq_778, FunctionCall target_1, PointerArithmeticOperation target_2, PointerArithmeticOperation target_3, FunctionCall target_4
where
not func_0(vimage_767, vexception_769, target_2, target_3, target_4)
and func_1(vimage_767, vq_778, target_1)
and func_2(vimage_767, target_2)
and func_3(vimage_767, vexception_769, vq_778, target_3)
and func_4(vimage_767, vexception_769, target_4)
and vimage_767.getType().hasName("Image *")
and vexception_769.getType().hasName("ExceptionInfo *")
and vq_778.getType().hasName("Quantum *")
and vimage_767.getParentScope+() = func
and vexception_769.getParentScope+() = func
and vq_778.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
