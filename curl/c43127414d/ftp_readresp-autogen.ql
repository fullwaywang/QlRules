/**
 * @name curl-c43127414d-ftp_readresp
 * @id cpp/curl/c43127414d/ftp-readresp
 * @description curl-c43127414d-lib/ftp.c-ftp_readresp CVE-2020-8231
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vconn_627, FunctionCall target_0) {
		target_0.getTarget().hasName("state")
		and not target_0.getTarget().hasName("_state")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vconn_627
}

from Function func, Variable vconn_627, FunctionCall target_0
where
func_0(vconn_627, target_0)
and vconn_627.getType().hasName("connectdata *")
and vconn_627.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
