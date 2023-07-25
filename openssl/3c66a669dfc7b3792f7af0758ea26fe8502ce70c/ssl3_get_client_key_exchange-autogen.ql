/**
 * @name openssl-3c66a669dfc7b3792f7af0758ea26fe8502ce70c-ssl3_get_client_key_exchange
 * @id cpp/openssl/3c66a669dfc7b3792f7af0758ea26fe8502ce70c/ssl3-get-client-key-exchange
 * @description openssl-3c66a669dfc7b3792f7af0758ea26fe8502ce70c-ssl3_get_client_key_exchange NULL
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vp_2130) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("BUF_strdup")
		and not target_0.getTarget().hasName("BUF_strndup")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vp_2130)
}

from Function func, Variable vp_2130
where
func_0(vp_2130)
and vp_2130.getType().hasName("unsigned char *")
and vp_2130.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
