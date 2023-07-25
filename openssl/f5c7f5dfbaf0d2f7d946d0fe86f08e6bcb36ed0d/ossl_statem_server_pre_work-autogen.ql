/**
 * @name openssl-f5c7f5dfbaf0d2f7d946d0fe86f08e6bcb36ed0d-ossl_statem_server_pre_work
 * @id cpp/openssl/f5c7f5dfbaf0d2f7d946d0fe86f08e6bcb36ed0d/ossl-statem-server-pre-work
 * @description openssl-f5c7f5dfbaf0d2f7d946d0fe86f08e6bcb36ed0d-ossl_statem_server_pre_work CVE-2016-2179
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_428) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("dtls1_clear_record_buffer")
		and not target_0.getTarget().hasName("dtls1_clear_sent_buffer")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vs_428)
}

from Function func, Parameter vs_428
where
func_0(vs_428)
and vs_428.getType().hasName("SSL *")
and vs_428.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
