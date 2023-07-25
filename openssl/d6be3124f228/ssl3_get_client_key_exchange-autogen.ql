/**
 * @name openssl-d6be3124f228-ssl3_get_client_key_exchange
 * @id cpp/openssl/d6be3124f228/ssl3-get-client-key-exchange
 * @description openssl-d6be3124f228-ssl/s3_srvr.c-ssl3_get_client_key_exchange CVE-2015-3196
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vp_2180, FunctionCall target_0) {
		target_0.getTarget().hasName("BUF_strdup")
		and not target_0.getTarget().hasName("BUF_strndup")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vp_2180
}

from Function func, Variable vp_2180, FunctionCall target_0
where
func_0(vp_2180, target_0)
and vp_2180.getType().hasName("unsigned char *")
and vp_2180.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
