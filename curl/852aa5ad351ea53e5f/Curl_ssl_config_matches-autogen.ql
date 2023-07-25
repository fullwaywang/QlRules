/**
 * @name curl-852aa5ad351ea53e5f-Curl_ssl_config_matches
 * @id cpp/curl/852aa5ad351ea53e5f/Curl-ssl-config-matches
 * @description curl-852aa5ad351ea53e5f-Curl_ssl_config_matches CVE-2022-22576
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vneedle_140, Parameter vdata_139) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("safecmp")
		and not target_0.getTarget().hasName("Curl_safecmp")
		and target_0.getArgument(0).(PointerFieldAccess).getTarget().getName()="CApath"
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_139
		and target_0.getArgument(1).(PointerFieldAccess).getTarget().getName()="CApath"
		and target_0.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_140)
}

predicate func_1(Parameter vneedle_140, Parameter vdata_139) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("safecmp")
		and not target_1.getTarget().hasName("Curl_safecmp")
		and target_1.getArgument(0).(PointerFieldAccess).getTarget().getName()="CAfile"
		and target_1.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_139
		and target_1.getArgument(1).(PointerFieldAccess).getTarget().getName()="CAfile"
		and target_1.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_140)
}

predicate func_2(Parameter vneedle_140, Parameter vdata_139) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("safecmp")
		and not target_2.getTarget().hasName("Curl_safecmp")
		and target_2.getArgument(0).(PointerFieldAccess).getTarget().getName()="issuercert"
		and target_2.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_139
		and target_2.getArgument(1).(PointerFieldAccess).getTarget().getName()="issuercert"
		and target_2.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_140)
}

predicate func_3(Parameter vneedle_140, Parameter vdata_139) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("safecmp")
		and not target_3.getTarget().hasName("Curl_safecmp")
		and target_3.getArgument(0).(PointerFieldAccess).getTarget().getName()="clientcert"
		and target_3.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_139
		and target_3.getArgument(1).(PointerFieldAccess).getTarget().getName()="clientcert"
		and target_3.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_140)
}

predicate func_4(Parameter vneedle_140, Parameter vdata_139) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("safecmp")
		and not target_4.getTarget().hasName("Curl_safecmp")
		and target_4.getArgument(0).(PointerFieldAccess).getTarget().getName()="random_file"
		and target_4.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_139
		and target_4.getArgument(1).(PointerFieldAccess).getTarget().getName()="random_file"
		and target_4.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_140)
}

predicate func_5(Parameter vneedle_140, Parameter vdata_139) {
	exists(FunctionCall target_5 |
		target_5.getTarget().hasName("safecmp")
		and not target_5.getTarget().hasName("Curl_safecmp")
		and target_5.getArgument(0).(PointerFieldAccess).getTarget().getName()="egdsocket"
		and target_5.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_139
		and target_5.getArgument(1).(PointerFieldAccess).getTarget().getName()="egdsocket"
		and target_5.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_140)
}

from Function func, Parameter vneedle_140, Parameter vdata_139
where
func_0(vneedle_140, vdata_139)
and func_1(vneedle_140, vdata_139)
and func_2(vneedle_140, vdata_139)
and func_3(vneedle_140, vdata_139)
and func_4(vneedle_140, vdata_139)
and func_5(vneedle_140, vdata_139)
and vneedle_140.getType().hasName("ssl_primary_config *")
and vdata_139.getType().hasName("ssl_primary_config *")
and vneedle_140.getParentScope+() = func
and vdata_139.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
