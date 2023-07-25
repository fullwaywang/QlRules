/**
 * @name curl-139a54ed0a172ada-Curl_http_output_auth
 * @id cpp/curl/139a54ed0a172ada/Curl-http-output-auth
 * @description curl-139a54ed0a172ada-Curl_http_output_auth CVE-2022-27774
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdata_808) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("allow_auth_to_host")
		and not target_0.getTarget().hasName("Curl_allow_auth_to_host")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vdata_808)
}

from Function func, Parameter vdata_808
where
func_0(vdata_808)
and vdata_808.getType().hasName("Curl_easy *")
and vdata_808.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
