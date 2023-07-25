/**
 * @name imagemagick-3cbfb163cff9e5b8cdeace8312e9bfee810ed02b-WaveletDenoiseImage
 * @id cpp/imagemagick/3cbfb163cff9e5b8cdeace8312e9bfee810ed02b/WaveletDenoiseImage
 * @description imagemagick-3cbfb163cff9e5b8cdeace8312e9bfee810ed02b-MagickCore/fx.c-WaveletDenoiseImage CVE-2016-9298
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(AddExpr target_0 |
		target_0.getAnOperand() instanceof ConditionalExpr
		and target_0.getAnOperand().(Literal).getValue()="1"
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("AcquireQuantumMemory")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0) instanceof ConditionalExpr
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(MulExpr).getLeftOperand().(FunctionCall).getTarget().hasName("GetOpenMPMaximumThreads")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(MulExpr).getRightOperand().(SizeofExprOperator).getValue()="4"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter vimage_5813, ConditionalExpr target_1) {
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="rows"
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_5813
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="columns"
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_5813
		and target_1.getThen().(PointerFieldAccess).getTarget().getName()="rows"
		and target_1.getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_5813
		and target_1.getElse().(PointerFieldAccess).getTarget().getName()="columns"
		and target_1.getElse().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_5813
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("AcquireQuantumMemory")
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(MulExpr).getLeftOperand().(FunctionCall).getTarget().hasName("GetOpenMPMaximumThreads")
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(MulExpr).getRightOperand().(SizeofExprOperator).getValue()="4"
}

from Function func, Parameter vimage_5813, ConditionalExpr target_1
where
not func_0(func)
and func_1(vimage_5813, target_1)
and vimage_5813.getType().hasName("const Image *")
and vimage_5813.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
