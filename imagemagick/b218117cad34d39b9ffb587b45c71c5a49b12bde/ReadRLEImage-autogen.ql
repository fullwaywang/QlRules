/**
 * @name imagemagick-b218117cad34d39b9ffb587b45c71c5a49b12bde-ReadRLEImage
 * @id cpp/imagemagick/b218117cad34d39b9ffb587b45c71c5a49b12bde/ReadRLEImage
 * @description imagemagick-b218117cad34d39b9ffb587b45c71c5a49b12bde-coders/rle.c-ReadRLEImage CVE-2017-7606
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("ScaleQuantumToChar")
		and target_0.getArgument(0) instanceof FunctionCall
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vimage_140, FunctionCall target_1) {
		target_1.getTarget().hasName("ScaleShortToQuantum")
		and target_1.getArgument(0).(FunctionCall).getTarget().hasName("ReadBlobLSBShort")
		and target_1.getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_140
}

from Function func, Variable vimage_140, FunctionCall target_1
where
not func_0(func)
and func_1(vimage_140, target_1)
and vimage_140.getType().hasName("Image *")
and vimage_140.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
