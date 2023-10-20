/**
 * @name httpd-67bd9bfe6c38831e14fe7122f1d84391472498f8-session_identity_decode
 * @id cpp/httpd/67bd9bfe6c38831e14fe7122f1d84391472498f8/session-identity-decode
 * @description httpd-67bd9bfe6c38831e14fe7122f1d84391472498f8-modules/session/mod_session.c-session_identity_decode CVE-2021-26690
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vpsep_414, FunctionCall target_1, VariableAccess target_0) {
		target_0.getTarget()=vpsep_414
		and target_0.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getTarget().hasName("apr_strtok")
		and target_0.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_0.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("char *")
		and target_1.getArgument(1).(VariableAccess).getLocation().isBefore(target_0.getLocation())
}

predicate func_1(Variable vpsep_414, FunctionCall target_1) {
		target_1.getTarget().hasName("apr_strtok")
		and target_1.getArgument(0).(VariableAccess).getTarget().getType().hasName("char *")
		and target_1.getArgument(1).(VariableAccess).getTarget()=vpsep_414
		and target_1.getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("char *")
}

from Function func, Variable vpsep_414, VariableAccess target_0, FunctionCall target_1
where
func_0(vpsep_414, target_1, target_0)
and func_1(vpsep_414, target_1)
and vpsep_414.getType().hasName("const char *")
and vpsep_414.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
