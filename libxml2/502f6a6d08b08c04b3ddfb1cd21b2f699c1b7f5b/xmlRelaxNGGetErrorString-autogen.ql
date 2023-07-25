/**
 * @name libxml2-502f6a6d08b08c04b3ddfb1cd21b2f699c1b7f5b-xmlRelaxNGGetErrorString
 * @id cpp/libxml2/502f6a6d08b08c04b3ddfb1cd21b2f699c1b7f5b/xmlRelaxNGGetErrorString
 * @description libxml2-502f6a6d08b08c04b3ddfb1cd21b2f699c1b7f5b-relaxng.c-xmlRelaxNGGetErrorString CVE-2016-4448
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vmsg_2090, FunctionCall target_0) {
		target_0.getTarget().hasName("xmlStrdup")
		and not target_0.getTarget().hasName("xmlCharStrdup")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vmsg_2090
}

predicate func_1(Function func) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("xmlEscapeFormatString")
		and target_1.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("xmlChar *")
		and target_1.getEnclosingFunction() = func)
}

from Function func, Variable vmsg_2090, FunctionCall target_0
where
func_0(vmsg_2090, target_0)
and not func_1(func)
and vmsg_2090.getType().hasName("char[1000]")
and vmsg_2090.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
