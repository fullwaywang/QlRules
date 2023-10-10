/**
 * @name curl-139a54ed0a172ada-Curl_add_custom_headers
 * @id cpp/curl/139a54ed0a172ada/Curl-add-custom-headers
 * @description curl-139a54ed0a172ada-Curl_add_custom_headers CVE-2022-27774
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdata_1789) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("allow_auth_to_host")
		and not target_0.getTarget().hasName("Curl_allow_auth_to_host")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vdata_1789)
}

from Function func, Parameter vdata_1789
where
func_0(vdata_1789)
and vdata_1789.getType().hasName("Curl_easy *")
and vdata_1789.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
