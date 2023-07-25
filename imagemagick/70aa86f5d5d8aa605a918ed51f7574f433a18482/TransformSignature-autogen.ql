/**
 * @name imagemagick-70aa86f5d5d8aa605a918ed51f7574f433a18482-TransformSignature
 * @id cpp/imagemagick/70aa86f5d5d8aa605a918ed51f7574f433a18482/TransformSignature
 * @description imagemagick-70aa86f5d5d8aa605a918ed51f7574f433a18482-MagickCore/signature.c-TransformSignature CVE-2021-20311
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vW_642, FunctionCall target_0) {
		target_0.getTarget().hasName("memset")
		and not target_0.getTarget().hasName("ResetMagickMemory")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vW_642
		and target_0.getArgument(1).(Literal).getValue()="0"
		and target_0.getArgument(2).(SizeofExprOperator).getValue()="256"
}

from Function func, Variable vW_642, FunctionCall target_0
where
func_0(vW_642, target_0)
and vW_642.getType().hasName("unsigned int[64]")
and vW_642.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
