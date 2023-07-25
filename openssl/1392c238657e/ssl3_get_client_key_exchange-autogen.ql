/**
 * @name openssl-1392c238657e-ssl3_get_client_key_exchange
 * @id cpp/openssl/1392c238657e/ssl3-get-client-key-exchange
 * @description openssl-1392c238657e-ssl/s3_srvr.c-ssl3_get_client_key_exchange CVE-2015-3196
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vp_1972, FunctionCall target_0) {
		target_0.getTarget().hasName("BUF_strdup")
		and not target_0.getTarget().hasName("BUF_strndup")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vp_1972
}

from Function func, Variable vp_1972, FunctionCall target_0
where
func_0(vp_1972, target_0)
and vp_1972.getType().hasName("unsigned char *")
and vp_1972.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
