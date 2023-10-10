/**
 * @name libtiff-46dc8fcd4d38c3b6f35ab28e532aee80e6f609d6-writeImageSections
 * @id cpp/libtiff/46dc8fcd4d38c3b6f35ab28e532aee80e6f609d6/writeImageSections
 * @description libtiff-46dc8fcd4d38c3b6f35ab28e532aee80e6f609d6-tools/tiffcrop.c-writeImageSections CVE-2022-0891
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vimage_7069, Variable vwidth_7075, MulExpr target_0) {
		target_0.getLeftOperand().(VariableAccess).getTarget()=vwidth_7075
		and target_0.getRightOperand().(PointerFieldAccess).getTarget().getName()="bps"
		and target_0.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_7069
		and target_0.getParent().(AddExpr).getParent().(DivExpr).getParent().(FunctionCall).getParent().(MulExpr).getLeftOperand().(FunctionCall).getTarget().hasName("ceil")
		and target_0.getParent().(AddExpr).getParent().(DivExpr).getParent().(FunctionCall).getParent().(MulExpr).getLeftOperand().(FunctionCall).getArgument(0).(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="7"
		and target_0.getParent().(AddExpr).getParent().(DivExpr).getParent().(FunctionCall).getParent().(MulExpr).getLeftOperand().(FunctionCall).getArgument(0).(DivExpr).getRightOperand().(Literal).getValue()="8"
}

from Function func, Parameter vimage_7069, Variable vwidth_7075, MulExpr target_0
where
func_0(vimage_7069, vwidth_7075, target_0)
and vimage_7069.getType().hasName("image_data *")
and vwidth_7075.getType().hasName("uint32_t")
and vimage_7069.getFunction() = func
and vwidth_7075.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
