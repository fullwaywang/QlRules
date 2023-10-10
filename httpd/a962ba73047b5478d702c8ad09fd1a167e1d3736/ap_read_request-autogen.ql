/**
 * @name httpd-a962ba73047b5478d702c8ad09fd1a167e1d3736-ap_read_request
 * @id cpp/httpd/a962ba73047b5478d702c8ad09fd1a167e1d3736/ap-read-request
 * @description httpd-a962ba73047b5478d702c8ad09fd1a167e1d3736-ap_read_request CVE-2021-44224
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vr_1426, FunctionCall target_0) {
		target_0.getTarget().hasName("ap_run_post_read_request")
		and not target_0.getTarget().hasName("ap_post_read_request")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vr_1426
}

from Function func, Variable vr_1426, FunctionCall target_0
where
func_0(vr_1426, target_0)
and vr_1426.getType().hasName("request_rec *")
and vr_1426.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
