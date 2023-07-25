/**
 * @name curl-c43127414d-InitiateTransfer
 * @id cpp/curl/c43127414d/InitiateTransfer
 * @description curl-c43127414d-lib/ftp.c-InitiateTransfer CVE-2020-8231
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vconn_485, FunctionCall target_0) {
		target_0.getTarget().hasName("state")
		and not target_0.getTarget().hasName("_state")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vconn_485
}

from Function func, Parameter vconn_485, FunctionCall target_0
where
func_0(vconn_485, target_0)
and vconn_485.getType().hasName("connectdata *")
and vconn_485.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
