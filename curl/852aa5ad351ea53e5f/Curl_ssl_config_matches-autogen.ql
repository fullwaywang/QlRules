import cpp

predicate func_0(Parameter vneedle, Parameter vdata) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("safecmp")
		and not target_0.getTarget().hasName("Curl_safecmp")
		and target_0.getType().hasName("bool")
		and target_0.getArgument(0).(PointerFieldAccess).getTarget().getName()="CApath"
		and target_0.getArgument(0).(PointerFieldAccess).getType().hasName("char *")
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_0.getArgument(1).(PointerFieldAccess).getTarget().getName()="CApath"
		and target_0.getArgument(1).(PointerFieldAccess).getType().hasName("char *")
		and target_0.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle)
}

predicate func_1(Parameter vneedle, Parameter vdata) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("safecmp")
		and not target_1.getTarget().hasName("Curl_safecmp")
		and target_1.getType().hasName("bool")
		and target_1.getArgument(0).(PointerFieldAccess).getTarget().getName()="CAfile"
		and target_1.getArgument(0).(PointerFieldAccess).getType().hasName("char *")
		and target_1.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_1.getArgument(1).(PointerFieldAccess).getTarget().getName()="CAfile"
		and target_1.getArgument(1).(PointerFieldAccess).getType().hasName("char *")
		and target_1.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle)
}

predicate func_2(Parameter vneedle, Parameter vdata) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("safecmp")
		and not target_2.getTarget().hasName("Curl_safecmp")
		and target_2.getType().hasName("bool")
		and target_2.getArgument(0).(PointerFieldAccess).getTarget().getName()="issuercert"
		and target_2.getArgument(0).(PointerFieldAccess).getType().hasName("char *")
		and target_2.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_2.getArgument(1).(PointerFieldAccess).getTarget().getName()="issuercert"
		and target_2.getArgument(1).(PointerFieldAccess).getType().hasName("char *")
		and target_2.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle)
}

predicate func_3(Parameter vneedle, Parameter vdata) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("safecmp")
		and not target_3.getTarget().hasName("Curl_safecmp")
		and target_3.getType().hasName("bool")
		and target_3.getArgument(0).(PointerFieldAccess).getTarget().getName()="clientcert"
		and target_3.getArgument(0).(PointerFieldAccess).getType().hasName("char *")
		and target_3.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_3.getArgument(1).(PointerFieldAccess).getTarget().getName()="clientcert"
		and target_3.getArgument(1).(PointerFieldAccess).getType().hasName("char *")
		and target_3.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle)
}

predicate func_4(Parameter vneedle, Parameter vdata) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("safecmp")
		and not target_4.getTarget().hasName("Curl_safecmp")
		and target_4.getType().hasName("bool")
		and target_4.getArgument(0).(PointerFieldAccess).getTarget().getName()="random_file"
		and target_4.getArgument(0).(PointerFieldAccess).getType().hasName("char *")
		and target_4.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_4.getArgument(1).(PointerFieldAccess).getTarget().getName()="random_file"
		and target_4.getArgument(1).(PointerFieldAccess).getType().hasName("char *")
		and target_4.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle)
}

predicate func_5(Parameter vneedle, Parameter vdata) {
	exists(FunctionCall target_5 |
		target_5.getTarget().hasName("safecmp")
		and not target_5.getTarget().hasName("Curl_safecmp")
		and target_5.getType().hasName("bool")
		and target_5.getArgument(0).(PointerFieldAccess).getTarget().getName()="egdsocket"
		and target_5.getArgument(0).(PointerFieldAccess).getType().hasName("char *")
		and target_5.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_5.getArgument(1).(PointerFieldAccess).getTarget().getName()="egdsocket"
		and target_5.getArgument(1).(PointerFieldAccess).getType().hasName("char *")
		and target_5.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle)
}

from Function func, Parameter vneedle, Parameter vdata
where
func_0(vneedle, vdata)
and func_1(vneedle, vdata)
and func_2(vneedle, vdata)
and func_3(vneedle, vdata)
and func_4(vneedle, vdata)
and func_5(vneedle, vdata)
and vneedle.getType().hasName("ssl_primary_config *")
and vdata.getType().hasName("ssl_primary_config *")
and vneedle.getParentScope+() = func
and vdata.getParentScope+() = func
select func, vneedle, vdata
