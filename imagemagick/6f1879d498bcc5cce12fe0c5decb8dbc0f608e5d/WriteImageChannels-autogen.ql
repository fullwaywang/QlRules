/**
 * @name imagemagick-6f1879d498bcc5cce12fe0c5decb8dbc0f608e5d-WriteImageChannels
 * @id cpp/imagemagick/6f1879d498bcc5cce12fe0c5decb8dbc0f608e5d/WriteImageChannels
 * @description imagemagick-6f1879d498bcc5cce12fe0c5decb8dbc0f608e5d-coders/psd.c-WriteImageChannels CVE-2016-7514
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(AddExpr target_0 |
		target_0.getAnOperand() instanceof MulExpr
		and target_0.getAnOperand().(Literal).getValue()="1"
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("AcquireQuantumMemory")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0) instanceof MulExpr
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(MulExpr).getRightOperand().(SizeofExprOperator).getValue()="1"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter vnext_image_2348, Variable vchannels_2352, MulExpr target_1) {
		target_1.getLeftOperand().(MulExpr).getLeftOperand().(Literal).getValue()="2"
		and target_1.getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vchannels_2352
		and target_1.getRightOperand().(PointerFieldAccess).getTarget().getName()="columns"
		and target_1.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnext_image_2348
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("AcquireQuantumMemory")
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(MulExpr).getRightOperand().(SizeofExprOperator).getValue()="1"
}

from Function func, Parameter vnext_image_2348, Variable vchannels_2352, MulExpr target_1
where
not func_0(func)
and func_1(vnext_image_2348, vchannels_2352, target_1)
and vnext_image_2348.getType().hasName("Image *")
and vchannels_2352.getType().hasName("size_t")
and vnext_image_2348.getParentScope+() = func
and vchannels_2352.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
