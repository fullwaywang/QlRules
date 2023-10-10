/**
 * @name libavif-0a8e7244d494ae98e9756355dfbfb6697ded2ff9-avifParseImageGridBox
 * @id cpp/libavif/0a8e7244d494ae98e9756355dfbfb6697ded2ff9/avifParseImageGridBox
 * @description libavif-0a8e7244d494ae98e9756355dfbfb6697ded2ff9-src/read.c-avifParseImageGridBox CVE-2020-36407
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vgrid_953, AddressOfExpr target_1, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="outputWidth"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgrid_953
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getLeftOperand().(MulExpr).getValue()="268435456"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="outputHeight"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgrid_953
		and target_0.getThen().(BlockStmt).getAStmt().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_1.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		or target_0.getCondition().(FunctionCall).getAnArgument().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgrid_953
		and target_0.getCondition().(FunctionCall).getAnArgument().(PointerFieldAccess).getTarget().getName()="outputWidth"
		and target_0.getCondition().(FunctionCall).getAnArgument().(PointerFieldAccess).getTarget().getName()="outputHeight"
	)
}

predicate func_1(Parameter vgrid_953, AddressOfExpr target_1) {
		target_1.getOperand().(PointerFieldAccess).getTarget().getName()="outputHeight"
		and target_1.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgrid_953
}

from Function func, Parameter vgrid_953, AddressOfExpr target_1
where
not func_0(vgrid_953, target_1, func)
and func_1(vgrid_953, target_1)
and vgrid_953.getType().hasName("avifImageGrid *")
and vgrid_953.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
