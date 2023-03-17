/**
 * @name httpd-a962ba73047b5478d702c8ad09fd1a167e1d3736-h2_request_create_rec
 * @id cpp/httpd/a962ba73047b5478d702c8ad09fd1a167e1d3736/h2-request-create-rec
 * @description httpd-a962ba73047b5478d702c8ad09fd1a167e1d3736-h2_request_create_rec CVE-2021-44224
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vr_275, FunctionCall target_0) {
		target_0.getTarget().hasName("ap_run_post_read_request")
		and not target_0.getTarget().hasName("ap_post_read_request")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vr_275
}

from Function func, Variable vr_275, FunctionCall target_0
where
func_0(vr_275, target_0)
and vr_275.getType().hasName("request_rec *")
and vr_275.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
