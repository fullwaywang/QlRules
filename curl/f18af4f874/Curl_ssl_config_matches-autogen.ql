import cpp

predicate func_0(Parameter vneedle, Parameter vdata) {
	exists(LogicalAndExpr target_0 |
		target_0.getType().hasName("int")
		and target_0.getLeftOperand().(LogicalAndExpr).getType().hasName("int")
		and target_0.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getType().hasName("int")
		and target_0.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(EQExpr).getType().hasName("int")
		and target_0.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="version"
		and target_0.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_0.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(EQExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="version"
		and target_0.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(EQExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle
		and target_0.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(EQExpr).getType().hasName("int")
		and target_0.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="version_max"
		and target_0.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_0.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(EQExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="version_max"
		and target_0.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(EQExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle
		and target_0.getLeftOperand().(LogicalAndExpr).getRightOperand().(EQExpr).getType().hasName("int")
		and target_0.getLeftOperand().(LogicalAndExpr).getRightOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="ssl_options"
		and target_0.getLeftOperand().(LogicalAndExpr).getRightOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getType().hasName("unsigned char")
		and target_0.getLeftOperand().(LogicalAndExpr).getRightOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_0.getLeftOperand().(LogicalAndExpr).getRightOperand().(EQExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="ssl_options"
		and target_0.getLeftOperand().(LogicalAndExpr).getRightOperand().(EQExpr).getRightOperand().(PointerFieldAccess).getType().hasName("unsigned char")
		and target_0.getLeftOperand().(LogicalAndExpr).getRightOperand().(EQExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle
		and target_0.getRightOperand().(EQExpr).getType().hasName("int")
		and target_0.getRightOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="verifypeer"
		and target_0.getRightOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getType().hasName("bit")
		and target_0.getRightOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_0.getRightOperand().(EQExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="verifypeer"
		and target_0.getRightOperand().(EQExpr).getRightOperand().(PointerFieldAccess).getType().hasName("bit")
		and target_0.getRightOperand().(EQExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle)
}

predicate func_1(Parameter vneedle, Parameter vdata) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("Curl_safe_strcasecompare")
		and target_1.getType().hasName("int")
		and target_1.getArgument(0).(PointerFieldAccess).getTarget().getName()="CRLfile"
		and target_1.getArgument(0).(PointerFieldAccess).getType().hasName("char *")
		and target_1.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_1.getArgument(1).(PointerFieldAccess).getTarget().getName()="CRLfile"
		and target_1.getArgument(1).(PointerFieldAccess).getType().hasName("char *")
		and target_1.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle)
}

predicate func_2(Parameter vneedle, Parameter vdata) {
	exists(LogicalAndExpr target_2 |
		target_2.getType().hasName("int")
		and target_2.getLeftOperand().(EQExpr).getType().hasName("int")
		and target_2.getLeftOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="version"
		and target_2.getLeftOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getType().hasName("long")
		and target_2.getLeftOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_2.getLeftOperand().(EQExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="version"
		and target_2.getLeftOperand().(EQExpr).getRightOperand().(PointerFieldAccess).getType().hasName("long")
		and target_2.getLeftOperand().(EQExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle
		and target_2.getRightOperand().(EQExpr).getType().hasName("int")
		and target_2.getRightOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="version_max"
		and target_2.getRightOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getType().hasName("long")
		and target_2.getRightOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_2.getRightOperand().(EQExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="version_max"
		and target_2.getRightOperand().(EQExpr).getRightOperand().(PointerFieldAccess).getType().hasName("long")
		and target_2.getRightOperand().(EQExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle)
}

predicate func_3(Parameter vneedle, Parameter vdata) {
	exists(EQExpr target_3 |
		target_3.getType().hasName("int")
		and target_3.getLeftOperand().(PointerFieldAccess).getTarget().getName()="verifypeer"
		and target_3.getLeftOperand().(PointerFieldAccess).getType().hasName("bit")
		and target_3.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_3.getRightOperand().(PointerFieldAccess).getTarget().getName()="verifypeer"
		and target_3.getRightOperand().(PointerFieldAccess).getType().hasName("bit")
		and target_3.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle)
}

predicate func_4(Parameter vneedle, Parameter vdata) {
	exists(EQExpr target_4 |
		target_4.getType().hasName("int")
		and target_4.getLeftOperand().(PointerFieldAccess).getTarget().getName()="verifyhost"
		and target_4.getLeftOperand().(PointerFieldAccess).getType().hasName("bit")
		and target_4.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_4.getRightOperand().(PointerFieldAccess).getTarget().getName()="verifyhost"
		and target_4.getRightOperand().(PointerFieldAccess).getType().hasName("bit")
		and target_4.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle)
}

predicate func_5(Parameter vneedle, Parameter vdata) {
	exists(EQExpr target_5 |
		target_5.getType().hasName("int")
		and target_5.getLeftOperand().(PointerFieldAccess).getTarget().getName()="verifystatus"
		and target_5.getLeftOperand().(PointerFieldAccess).getType().hasName("bit")
		and target_5.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_5.getRightOperand().(PointerFieldAccess).getTarget().getName()="verifystatus"
		and target_5.getRightOperand().(PointerFieldAccess).getType().hasName("bit")
		and target_5.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle)
}

predicate func_6(Parameter vneedle, Parameter vdata) {
	exists(FunctionCall target_6 |
		target_6.getTarget().hasName("blobcmp")
		and target_6.getType().hasName("bool")
		and target_6.getArgument(0).(PointerFieldAccess).getTarget().getName()="cert_blob"
		and target_6.getArgument(0).(PointerFieldAccess).getType().hasName("curl_blob *")
		and target_6.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_6.getArgument(1).(PointerFieldAccess).getTarget().getName()="cert_blob"
		and target_6.getArgument(1).(PointerFieldAccess).getType().hasName("curl_blob *")
		and target_6.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle)
}

predicate func_7(Parameter vneedle, Parameter vdata) {
	exists(FunctionCall target_7 |
		target_7.getTarget().hasName("blobcmp")
		and target_7.getType().hasName("bool")
		and target_7.getArgument(0).(PointerFieldAccess).getTarget().getName()="ca_info_blob"
		and target_7.getArgument(0).(PointerFieldAccess).getType().hasName("curl_blob *")
		and target_7.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_7.getArgument(1).(PointerFieldAccess).getTarget().getName()="ca_info_blob"
		and target_7.getArgument(1).(PointerFieldAccess).getType().hasName("curl_blob *")
		and target_7.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle)
}

predicate func_8(Parameter vneedle, Parameter vdata) {
	exists(FunctionCall target_8 |
		target_8.getTarget().hasName("blobcmp")
		and target_8.getType().hasName("bool")
		and target_8.getArgument(0).(PointerFieldAccess).getTarget().getName()="issuercert_blob"
		and target_8.getArgument(0).(PointerFieldAccess).getType().hasName("curl_blob *")
		and target_8.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_8.getArgument(1).(PointerFieldAccess).getTarget().getName()="issuercert_blob"
		and target_8.getArgument(1).(PointerFieldAccess).getType().hasName("curl_blob *")
		and target_8.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle)
}

predicate func_9(Parameter vneedle, Parameter vdata) {
	exists(FunctionCall target_9 |
		target_9.getTarget().hasName("Curl_safecmp")
		and target_9.getType().hasName("bool")
		and target_9.getArgument(0).(PointerFieldAccess).getTarget().getName()="CApath"
		and target_9.getArgument(0).(PointerFieldAccess).getType().hasName("char *")
		and target_9.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_9.getArgument(1).(PointerFieldAccess).getTarget().getName()="CApath"
		and target_9.getArgument(1).(PointerFieldAccess).getType().hasName("char *")
		and target_9.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle)
}

predicate func_10(Parameter vneedle, Parameter vdata) {
	exists(FunctionCall target_10 |
		target_10.getTarget().hasName("Curl_safecmp")
		and target_10.getType().hasName("bool")
		and target_10.getArgument(0).(PointerFieldAccess).getTarget().getName()="CAfile"
		and target_10.getArgument(0).(PointerFieldAccess).getType().hasName("char *")
		and target_10.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_10.getArgument(1).(PointerFieldAccess).getTarget().getName()="CAfile"
		and target_10.getArgument(1).(PointerFieldAccess).getType().hasName("char *")
		and target_10.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle)
}

predicate func_11(Parameter vneedle, Parameter vdata) {
	exists(FunctionCall target_11 |
		target_11.getTarget().hasName("Curl_safecmp")
		and target_11.getType().hasName("bool")
		and target_11.getArgument(0).(PointerFieldAccess).getTarget().getName()="issuercert"
		and target_11.getArgument(0).(PointerFieldAccess).getType().hasName("char *")
		and target_11.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_11.getArgument(1).(PointerFieldAccess).getTarget().getName()="issuercert"
		and target_11.getArgument(1).(PointerFieldAccess).getType().hasName("char *")
		and target_11.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle)
}

predicate func_12(Parameter vneedle, Parameter vdata) {
	exists(FunctionCall target_12 |
		target_12.getTarget().hasName("Curl_safecmp")
		and target_12.getType().hasName("bool")
		and target_12.getArgument(0).(PointerFieldAccess).getTarget().getName()="clientcert"
		and target_12.getArgument(0).(PointerFieldAccess).getType().hasName("char *")
		and target_12.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_12.getArgument(1).(PointerFieldAccess).getTarget().getName()="clientcert"
		and target_12.getArgument(1).(PointerFieldAccess).getType().hasName("char *")
		and target_12.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle)
}

predicate func_13(Parameter vneedle, Parameter vdata) {
	exists(FunctionCall target_13 |
		target_13.getTarget().hasName("Curl_safecmp")
		and target_13.getType().hasName("bool")
		and target_13.getArgument(0).(PointerFieldAccess).getTarget().getName()="random_file"
		and target_13.getArgument(0).(PointerFieldAccess).getType().hasName("char *")
		and target_13.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_13.getArgument(1).(PointerFieldAccess).getTarget().getName()="random_file"
		and target_13.getArgument(1).(PointerFieldAccess).getType().hasName("char *")
		and target_13.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle)
}

predicate func_14(Parameter vneedle, Parameter vdata) {
	exists(FunctionCall target_14 |
		target_14.getTarget().hasName("Curl_safecmp")
		and target_14.getType().hasName("bool")
		and target_14.getArgument(0).(PointerFieldAccess).getTarget().getName()="egdsocket"
		and target_14.getArgument(0).(PointerFieldAccess).getType().hasName("char *")
		and target_14.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_14.getArgument(1).(PointerFieldAccess).getTarget().getName()="egdsocket"
		and target_14.getArgument(1).(PointerFieldAccess).getType().hasName("char *")
		and target_14.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle)
}

predicate func_15(Parameter vneedle, Parameter vdata) {
	exists(FunctionCall target_15 |
		target_15.getTarget().hasName("Curl_safe_strcasecompare")
		and target_15.getType().hasName("int")
		and target_15.getArgument(0).(PointerFieldAccess).getTarget().getName()="cipher_list"
		and target_15.getArgument(0).(PointerFieldAccess).getType().hasName("char *")
		and target_15.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_15.getArgument(1).(PointerFieldAccess).getTarget().getName()="cipher_list"
		and target_15.getArgument(1).(PointerFieldAccess).getType().hasName("char *")
		and target_15.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle)
}

predicate func_16(Parameter vneedle, Parameter vdata) {
	exists(FunctionCall target_16 |
		target_16.getTarget().hasName("Curl_safe_strcasecompare")
		and target_16.getType().hasName("int")
		and target_16.getArgument(0).(PointerFieldAccess).getTarget().getName()="cipher_list13"
		and target_16.getArgument(0).(PointerFieldAccess).getType().hasName("char *")
		and target_16.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_16.getArgument(1).(PointerFieldAccess).getTarget().getName()="cipher_list13"
		and target_16.getArgument(1).(PointerFieldAccess).getType().hasName("char *")
		and target_16.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle)
}

predicate func_17(Parameter vneedle, Parameter vdata) {
	exists(FunctionCall target_17 |
		target_17.getTarget().hasName("Curl_safe_strcasecompare")
		and target_17.getType().hasName("int")
		and target_17.getArgument(0).(PointerFieldAccess).getTarget().getName()="curves"
		and target_17.getArgument(0).(PointerFieldAccess).getType().hasName("char *")
		and target_17.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_17.getArgument(1).(PointerFieldAccess).getTarget().getName()="curves"
		and target_17.getArgument(1).(PointerFieldAccess).getType().hasName("char *")
		and target_17.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle)
}

from Function func, Parameter vneedle, Parameter vdata
where
not func_0(vneedle, vdata)
and not func_1(vneedle, vdata)
and func_2(vneedle, vdata)
and func_3(vneedle, vdata)
and func_4(vneedle, vdata)
and func_5(vneedle, vdata)
and func_6(vneedle, vdata)
and func_7(vneedle, vdata)
and func_8(vneedle, vdata)
and func_9(vneedle, vdata)
and func_10(vneedle, vdata)
and func_11(vneedle, vdata)
and func_12(vneedle, vdata)
and func_13(vneedle, vdata)
and func_14(vneedle, vdata)
and func_15(vneedle, vdata)
and func_16(vneedle, vdata)
and func_17(vneedle, vdata)
and vneedle.getType().hasName("ssl_primary_config *")
and vdata.getType().hasName("ssl_primary_config *")
and vneedle.getParentScope+() = func
and vdata.getParentScope+() = func
select func, vneedle, vdata
