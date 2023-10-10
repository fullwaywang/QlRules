/**
 * @name curl-e8cea8d70fed7ad5e14d8b3e871ebf0ea0bf53b0-Curl_dupset
 * @id cpp/curl/e8cea8d70fed7ad5e14d8b3e871ebf0ea0bf53b0/Curl-dupset
 * @description curl-e8cea8d70fed7ad5e14d8b3e871ebf0ea0bf53b0-lib/url.c-Curl_dupset CVE-2014-3707
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("curlx_sotouz")
		and target_0.getArgument(0) instanceof ValueFieldAccess
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter vsrc_348, ValueFieldAccess target_1) {
		target_1.getTarget().getName()="postfieldsize"
		and target_1.getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_1.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsrc_348
}

from Function func, Parameter vsrc_348, ValueFieldAccess target_1
where
not func_0(func)
and func_1(vsrc_348, target_1)
and vsrc_348.getType().hasName("SessionHandle *")
and vsrc_348.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
