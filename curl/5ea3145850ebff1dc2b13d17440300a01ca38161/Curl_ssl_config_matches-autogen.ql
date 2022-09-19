import cpp

predicate func_0(Parameter vneedle, Parameter vdata) {
	exists(LogicalAndExpr target_0 |
		target_0.getType().hasName("int")
		and target_0.getLeftOperand().(LogicalAndExpr).getType().hasName("int")
		and target_0.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getType().hasName("int")
		and target_0.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getType().hasName("int")
		and target_0.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="version"
		and target_0.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_0.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(EQExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="version"
		and target_0.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(EQExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle
		and target_0.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="version_max"
		and target_0.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_0.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(EQExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="version_max"
		and target_0.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(EQExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle
		and target_0.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="verifypeer"
		and target_0.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_0.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(EQExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="verifypeer"
		and target_0.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(EQExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle
		and target_0.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="verifyhost"
		and target_0.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_0.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(EQExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="verifyhost"
		and target_0.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(EQExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle
		and target_0.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="verifystatus"
		and target_0.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_0.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(EQExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="verifystatus"
		and target_0.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(EQExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle
		and target_0.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(FunctionCall).getTarget().hasName("blobcmp")
		and target_0.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="cert_blob"
		and target_0.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_0.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="cert_blob"
		and target_0.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle
		and target_0.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(FunctionCall).getTarget().hasName("blobcmp")
		and target_0.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(FunctionCall).getType().hasName("bool")
		and target_0.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ca_info_blob"
		and target_0.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_0.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="ca_info_blob"
		and target_0.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle
		and target_0.getLeftOperand().(LogicalAndExpr).getRightOperand().(FunctionCall).getTarget().hasName("blobcmp")
		and target_0.getLeftOperand().(LogicalAndExpr).getRightOperand().(FunctionCall).getType().hasName("bool")
		and target_0.getLeftOperand().(LogicalAndExpr).getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="issuercert_blob"
		and target_0.getLeftOperand().(LogicalAndExpr).getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getType().hasName("curl_blob *")
		and target_0.getLeftOperand().(LogicalAndExpr).getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_0.getLeftOperand().(LogicalAndExpr).getRightOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="issuercert_blob"
		and target_0.getLeftOperand().(LogicalAndExpr).getRightOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getType().hasName("curl_blob *")
		and target_0.getLeftOperand().(LogicalAndExpr).getRightOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle
		and target_0.getRightOperand().(FunctionCall).getTarget().hasName("safecmp")
		and target_0.getRightOperand().(FunctionCall).getType().hasName("bool")
		and target_0.getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="CApath"
		and target_0.getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getType().hasName("char *")
		and target_0.getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_0.getRightOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="CApath"
		and target_0.getRightOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getType().hasName("char *")
		and target_0.getRightOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle)
}

predicate func_1(Parameter vneedle, Parameter vdata) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("safecmp")
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
		and target_5.getType().hasName("bool")
		and target_5.getArgument(0).(PointerFieldAccess).getTarget().getName()="egdsocket"
		and target_5.getArgument(0).(PointerFieldAccess).getType().hasName("char *")
		and target_5.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_5.getArgument(1).(PointerFieldAccess).getTarget().getName()="egdsocket"
		and target_5.getArgument(1).(PointerFieldAccess).getType().hasName("char *")
		and target_5.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle)
}

predicate func_6(Parameter vneedle, Parameter vdata) {
	exists(LogicalAndExpr target_6 |
		target_6.getType().hasName("int")
		and target_6.getLeftOperand().(LogicalAndExpr).getType().hasName("int")
		and target_6.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getType().hasName("int")
		and target_6.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getType().hasName("int")
		and target_6.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="version"
		and target_6.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_6.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(EQExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="version"
		and target_6.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(EQExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle
		and target_6.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="version_max"
		and target_6.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_6.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(EQExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="version_max"
		and target_6.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(EQExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle
		and target_6.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="verifypeer"
		and target_6.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_6.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(EQExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="verifypeer"
		and target_6.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(EQExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle
		and target_6.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="verifyhost"
		and target_6.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_6.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(EQExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="verifyhost"
		and target_6.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(EQExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle
		and target_6.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(EQExpr).getType().hasName("int")
		and target_6.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="verifystatus"
		and target_6.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(EQExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_6.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(EQExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="verifystatus"
		and target_6.getLeftOperand().(LogicalAndExpr).getLeftOperand().(LogicalAndExpr).getRightOperand().(EQExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle
		and target_6.getLeftOperand().(LogicalAndExpr).getRightOperand().(FunctionCall).getTarget().hasName("blobcmp")
		and target_6.getLeftOperand().(LogicalAndExpr).getRightOperand().(FunctionCall).getType().hasName("bool")
		and target_6.getLeftOperand().(LogicalAndExpr).getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="cert_blob"
		and target_6.getLeftOperand().(LogicalAndExpr).getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getType().hasName("curl_blob *")
		and target_6.getLeftOperand().(LogicalAndExpr).getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_6.getLeftOperand().(LogicalAndExpr).getRightOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="cert_blob"
		and target_6.getLeftOperand().(LogicalAndExpr).getRightOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getType().hasName("curl_blob *")
		and target_6.getLeftOperand().(LogicalAndExpr).getRightOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle
		and target_6.getRightOperand().(FunctionCall).getTarget().hasName("blobcmp")
		and target_6.getRightOperand().(FunctionCall).getType().hasName("bool")
		and target_6.getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ca_info_blob"
		and target_6.getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getType().hasName("curl_blob *")
		and target_6.getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata
		and target_6.getRightOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="ca_info_blob"
		and target_6.getRightOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getType().hasName("curl_blob *")
		and target_6.getRightOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle)
}

predicate func_7(Parameter vdata) {
	exists(PointerFieldAccess target_7 |
		target_7.getTarget().getName()="CApath"
		and target_7.getType().hasName("char *")
		and target_7.getQualifier().(VariableAccess).getTarget()=vdata)
}

predicate func_8(Parameter vneedle) {
	exists(PointerFieldAccess target_8 |
		target_8.getTarget().getName()="CApath"
		and target_8.getType().hasName("char *")
		and target_8.getQualifier().(VariableAccess).getTarget()=vneedle)
}

predicate func_9(Parameter vdata) {
	exists(PointerFieldAccess target_9 |
		target_9.getTarget().getName()="CAfile"
		and target_9.getType().hasName("char *")
		and target_9.getQualifier().(VariableAccess).getTarget()=vdata)
}

predicate func_10(Parameter vneedle) {
	exists(PointerFieldAccess target_10 |
		target_10.getTarget().getName()="CAfile"
		and target_10.getType().hasName("char *")
		and target_10.getQualifier().(VariableAccess).getTarget()=vneedle)
}

predicate func_11(Parameter vdata) {
	exists(PointerFieldAccess target_11 |
		target_11.getTarget().getName()="clientcert"
		and target_11.getType().hasName("char *")
		and target_11.getQualifier().(VariableAccess).getTarget()=vdata)
}

predicate func_12(Parameter vneedle) {
	exists(PointerFieldAccess target_12 |
		target_12.getTarget().getName()="clientcert"
		and target_12.getType().hasName("char *")
		and target_12.getQualifier().(VariableAccess).getTarget()=vneedle)
}

predicate func_13(Parameter vdata) {
	exists(PointerFieldAccess target_13 |
		target_13.getTarget().getName()="random_file"
		and target_13.getType().hasName("char *")
		and target_13.getQualifier().(VariableAccess).getTarget()=vdata)
}

predicate func_14(Parameter vneedle) {
	exists(PointerFieldAccess target_14 |
		target_14.getTarget().getName()="random_file"
		and target_14.getType().hasName("char *")
		and target_14.getQualifier().(VariableAccess).getTarget()=vneedle)
}

predicate func_15(Parameter vdata) {
	exists(PointerFieldAccess target_15 |
		target_15.getTarget().getName()="egdsocket"
		and target_15.getType().hasName("char *")
		and target_15.getQualifier().(VariableAccess).getTarget()=vdata)
}

predicate func_16(Parameter vneedle) {
	exists(PointerFieldAccess target_16 |
		target_16.getTarget().getName()="egdsocket"
		and target_16.getType().hasName("char *")
		and target_16.getQualifier().(VariableAccess).getTarget()=vneedle)
}

predicate func_17(Function func) {
	exists(FunctionCall target_17 |
		target_17.getTarget().hasName("Curl_safe_strcasecompare")
		and target_17.getType().hasName("int")
		and target_17.getArgument(0) instanceof PointerFieldAccess
		and target_17.getArgument(1) instanceof PointerFieldAccess
		and target_17.getEnclosingFunction() = func)
}

predicate func_18(Function func) {
	exists(FunctionCall target_18 |
		target_18.getTarget().hasName("Curl_safe_strcasecompare")
		and target_18.getType().hasName("int")
		and target_18.getArgument(0) instanceof PointerFieldAccess
		and target_18.getArgument(1) instanceof PointerFieldAccess
		and target_18.getEnclosingFunction() = func)
}

predicate func_19(Function func) {
	exists(FunctionCall target_19 |
		target_19.getTarget().hasName("Curl_safe_strcasecompare")
		and target_19.getType().hasName("int")
		and target_19.getArgument(0) instanceof PointerFieldAccess
		and target_19.getArgument(1) instanceof PointerFieldAccess
		and target_19.getEnclosingFunction() = func)
}

predicate func_20(Function func) {
	exists(FunctionCall target_20 |
		target_20.getTarget().hasName("Curl_safe_strcasecompare")
		and target_20.getType().hasName("int")
		and target_20.getArgument(0) instanceof PointerFieldAccess
		and target_20.getArgument(1) instanceof PointerFieldAccess
		and target_20.getEnclosingFunction() = func)
}

predicate func_21(Function func) {
	exists(FunctionCall target_21 |
		target_21.getTarget().hasName("Curl_safe_strcasecompare")
		and target_21.getType().hasName("int")
		and target_21.getArgument(0) instanceof PointerFieldAccess
		and target_21.getArgument(1) instanceof PointerFieldAccess
		and target_21.getEnclosingFunction() = func)
}

from Function func, Parameter vneedle, Parameter vdata
where
not func_0(vneedle, vdata)
and not func_1(vneedle, vdata)
and not func_2(vneedle, vdata)
and not func_3(vneedle, vdata)
and not func_4(vneedle, vdata)
and not func_5(vneedle, vdata)
and func_6(vneedle, vdata)
and func_7(vdata)
and func_8(vneedle)
and func_9(vdata)
and func_10(vneedle)
and func_11(vdata)
and func_12(vneedle)
and func_13(vdata)
and func_14(vneedle)
and func_15(vdata)
and func_16(vneedle)
and func_17(func)
and func_18(func)
and func_19(func)
and func_20(func)
and func_21(func)
and vneedle.getType().hasName("ssl_primary_config *")
and vdata.getType().hasName("ssl_primary_config *")
and vneedle.getParentScope+() = func
and vdata.getParentScope+() = func
select func, vneedle, vdata
