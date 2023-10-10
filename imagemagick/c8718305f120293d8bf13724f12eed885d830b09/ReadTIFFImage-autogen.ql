/**
 * @name imagemagick-c8718305f120293d8bf13724f12eed885d830b09-ReadTIFFImage
 * @id cpp/imagemagick/c8718305f120293d8bf13724f12eed885d830b09/ReadTIFFImage
 * @description imagemagick-c8718305f120293d8bf13724f12eed885d830b09-coders/tiff.c-ReadTIFFImage CVE-2022-1115
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(MulExpr target_0 |
		target_0.getLeftOperand().(Literal).getValue()="4"
		and target_0.getRightOperand() instanceof ConditionalExpr
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vtiff_1235, Variable vrows_1976, ConditionalExpr target_1) {
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vrows_1976
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getRightOperand().(FunctionCall).getTarget().hasName("TIFFTileRowSize")
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getRightOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtiff_1235
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("TIFFTileSize")
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtiff_1235
		and target_1.getThen().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vrows_1976
		and target_1.getThen().(MulExpr).getRightOperand().(FunctionCall).getTarget().hasName("TIFFTileRowSize")
		and target_1.getThen().(MulExpr).getRightOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtiff_1235
		and target_1.getElse().(FunctionCall).getTarget().hasName("TIFFTileSize")
		and target_1.getElse().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtiff_1235
		and target_1.getParent().(AssignExpr).getRValue() = target_1
}

from Function func, Variable vtiff_1235, Variable vrows_1976, ConditionalExpr target_1
where
not func_0(func)
and func_1(vtiff_1235, vrows_1976, target_1)
and vtiff_1235.getType().hasName("TIFF *")
and vrows_1976.getType().hasName("uint32")
and vtiff_1235.getParentScope+() = func
and vrows_1976.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
