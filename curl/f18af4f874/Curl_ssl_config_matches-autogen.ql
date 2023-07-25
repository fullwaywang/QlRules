/**
 * @name curl-f18af4f874-Curl_ssl_config_matches
 * @id cpp/curl/f18af4f874/Curl-ssl-config-matches
 * @description curl-f18af4f874-Curl_ssl_config_matches CVE-2022-27782
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdata_130, Parameter vneedle_131) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand() instanceof LogicalAndExpr
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="ssl_options"
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_130
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="ssl_options"
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_131
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_0.getAnOperand() instanceof FunctionCall)
}

predicate func_1(Parameter vdata_130, Parameter vneedle_131) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("Curl_safecmp")
		and target_1.getArgument(0).(PointerFieldAccess).getTarget().getName()="username"
		and target_1.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_130
		and target_1.getArgument(1).(PointerFieldAccess).getTarget().getName()="username"
		and target_1.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_131)
}

predicate func_2(Parameter vdata_130, Parameter vneedle_131) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("Curl_safecmp")
		and target_2.getArgument(0).(PointerFieldAccess).getTarget().getName()="password"
		and target_2.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_130
		and target_2.getArgument(1).(PointerFieldAccess).getTarget().getName()="password"
		and target_2.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_131)
}

predicate func_3(Parameter vdata_130, Parameter vneedle_131) {
	exists(EqualityOperation target_3 |
		target_3.getAnOperand().(PointerFieldAccess).getTarget().getName()="authtype"
		and target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_130
		and target_3.getAnOperand().(PointerFieldAccess).getTarget().getName()="authtype"
		and target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_131)
}

predicate func_4(Parameter vdata_130, Parameter vneedle_131) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("Curl_safe_strcasecompare")
		and target_4.getArgument(0).(PointerFieldAccess).getTarget().getName()="CRLfile"
		and target_4.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_130
		and target_4.getArgument(1).(PointerFieldAccess).getTarget().getName()="CRLfile"
		and target_4.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_131)
}

predicate func_5(Parameter vdata_130, Parameter vneedle_131) {
	exists(LogicalAndExpr target_5 |
		target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="version"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_130
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="version"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_131
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="version_max"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_130
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="version_max"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_131)
}

predicate func_6(Parameter vdata_130, Parameter vneedle_131) {
	exists(EqualityOperation target_6 |
		target_6.getAnOperand().(PointerFieldAccess).getTarget().getName()="verifypeer"
		and target_6.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_130
		and target_6.getAnOperand().(PointerFieldAccess).getTarget().getName()="verifypeer"
		and target_6.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_131)
}

predicate func_7(Parameter vdata_130, Parameter vneedle_131) {
	exists(EqualityOperation target_7 |
		target_7.getAnOperand().(PointerFieldAccess).getTarget().getName()="verifyhost"
		and target_7.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_130
		and target_7.getAnOperand().(PointerFieldAccess).getTarget().getName()="verifyhost"
		and target_7.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_131)
}

predicate func_8(Parameter vdata_130, Parameter vneedle_131) {
	exists(EqualityOperation target_8 |
		target_8.getAnOperand().(PointerFieldAccess).getTarget().getName()="verifystatus"
		and target_8.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_130
		and target_8.getAnOperand().(PointerFieldAccess).getTarget().getName()="verifystatus"
		and target_8.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_131)
}

predicate func_9(Parameter vdata_130, Parameter vneedle_131) {
	exists(FunctionCall target_9 |
		target_9.getTarget().hasName("blobcmp")
		and target_9.getArgument(0).(PointerFieldAccess).getTarget().getName()="cert_blob"
		and target_9.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_130
		and target_9.getArgument(1).(PointerFieldAccess).getTarget().getName()="cert_blob"
		and target_9.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_131)
}

predicate func_10(Parameter vdata_130, Parameter vneedle_131) {
	exists(FunctionCall target_10 |
		target_10.getTarget().hasName("blobcmp")
		and target_10.getArgument(0).(PointerFieldAccess).getTarget().getName()="ca_info_blob"
		and target_10.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_130
		and target_10.getArgument(1).(PointerFieldAccess).getTarget().getName()="ca_info_blob"
		and target_10.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_131)
}

predicate func_11(Parameter vdata_130, Parameter vneedle_131) {
	exists(FunctionCall target_11 |
		target_11.getTarget().hasName("blobcmp")
		and target_11.getArgument(0).(PointerFieldAccess).getTarget().getName()="issuercert_blob"
		and target_11.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_130
		and target_11.getArgument(1).(PointerFieldAccess).getTarget().getName()="issuercert_blob"
		and target_11.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_131)
}

predicate func_12(Parameter vdata_130, Parameter vneedle_131) {
	exists(FunctionCall target_12 |
		target_12.getTarget().hasName("Curl_safecmp")
		and target_12.getArgument(0).(PointerFieldAccess).getTarget().getName()="CApath"
		and target_12.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_130
		and target_12.getArgument(1).(PointerFieldAccess).getTarget().getName()="CApath"
		and target_12.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_131)
}

predicate func_13(Parameter vdata_130, Parameter vneedle_131) {
	exists(FunctionCall target_13 |
		target_13.getTarget().hasName("Curl_safecmp")
		and target_13.getArgument(0).(PointerFieldAccess).getTarget().getName()="CAfile"
		and target_13.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_130
		and target_13.getArgument(1).(PointerFieldAccess).getTarget().getName()="CAfile"
		and target_13.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_131)
}

predicate func_14(Parameter vdata_130, Parameter vneedle_131) {
	exists(FunctionCall target_14 |
		target_14.getTarget().hasName("Curl_safecmp")
		and target_14.getArgument(0).(PointerFieldAccess).getTarget().getName()="issuercert"
		and target_14.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_130
		and target_14.getArgument(1).(PointerFieldAccess).getTarget().getName()="issuercert"
		and target_14.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_131)
}

predicate func_15(Parameter vdata_130, Parameter vneedle_131) {
	exists(FunctionCall target_15 |
		target_15.getTarget().hasName("Curl_safecmp")
		and target_15.getArgument(0).(PointerFieldAccess).getTarget().getName()="clientcert"
		and target_15.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_130
		and target_15.getArgument(1).(PointerFieldAccess).getTarget().getName()="clientcert"
		and target_15.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_131)
}

predicate func_16(Parameter vdata_130, Parameter vneedle_131) {
	exists(FunctionCall target_16 |
		target_16.getTarget().hasName("Curl_safecmp")
		and target_16.getArgument(0).(PointerFieldAccess).getTarget().getName()="random_file"
		and target_16.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_130
		and target_16.getArgument(1).(PointerFieldAccess).getTarget().getName()="random_file"
		and target_16.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_131)
}

predicate func_17(Parameter vdata_130, Parameter vneedle_131) {
	exists(FunctionCall target_17 |
		target_17.getTarget().hasName("Curl_safecmp")
		and target_17.getArgument(0).(PointerFieldAccess).getTarget().getName()="egdsocket"
		and target_17.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_130
		and target_17.getArgument(1).(PointerFieldAccess).getTarget().getName()="egdsocket"
		and target_17.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_131)
}

predicate func_18(Parameter vdata_130, Parameter vneedle_131) {
	exists(FunctionCall target_18 |
		target_18.getTarget().hasName("Curl_safe_strcasecompare")
		and target_18.getArgument(0).(PointerFieldAccess).getTarget().getName()="cipher_list"
		and target_18.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_130
		and target_18.getArgument(1).(PointerFieldAccess).getTarget().getName()="cipher_list"
		and target_18.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_131)
}

predicate func_19(Parameter vdata_130, Parameter vneedle_131) {
	exists(FunctionCall target_19 |
		target_19.getTarget().hasName("Curl_safe_strcasecompare")
		and target_19.getArgument(0).(PointerFieldAccess).getTarget().getName()="cipher_list13"
		and target_19.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_130
		and target_19.getArgument(1).(PointerFieldAccess).getTarget().getName()="cipher_list13"
		and target_19.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_131)
}

predicate func_20(Parameter vdata_130, Parameter vneedle_131) {
	exists(FunctionCall target_20 |
		target_20.getTarget().hasName("Curl_safe_strcasecompare")
		and target_20.getArgument(0).(PointerFieldAccess).getTarget().getName()="curves"
		and target_20.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_130
		and target_20.getArgument(1).(PointerFieldAccess).getTarget().getName()="curves"
		and target_20.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_131)
}

predicate func_21(Parameter vdata_130) {
	exists(PointerFieldAccess target_21 |
		target_21.getTarget().getName()="CAfile"
		and target_21.getQualifier().(VariableAccess).getTarget()=vdata_130)
}

predicate func_22(Parameter vdata_130) {
	exists(PointerFieldAccess target_22 |
		target_22.getTarget().getName()="issuercert"
		and target_22.getQualifier().(VariableAccess).getTarget()=vdata_130)
}

predicate func_23(Parameter vdata_130) {
	exists(PointerFieldAccess target_23 |
		target_23.getTarget().getName()="clientcert"
		and target_23.getQualifier().(VariableAccess).getTarget()=vdata_130)
}

predicate func_24(Parameter vdata_130) {
	exists(PointerFieldAccess target_24 |
		target_24.getTarget().getName()="cipher_list13"
		and target_24.getQualifier().(VariableAccess).getTarget()=vdata_130)
}

predicate func_25(Parameter vneedle_131) {
	exists(PointerFieldAccess target_25 |
		target_25.getTarget().getName()="CAfile"
		and target_25.getQualifier().(VariableAccess).getTarget()=vneedle_131)
}

predicate func_26(Parameter vneedle_131) {
	exists(PointerFieldAccess target_26 |
		target_26.getTarget().getName()="issuercert"
		and target_26.getQualifier().(VariableAccess).getTarget()=vneedle_131)
}

predicate func_27(Parameter vneedle_131) {
	exists(PointerFieldAccess target_27 |
		target_27.getTarget().getName()="clientcert"
		and target_27.getQualifier().(VariableAccess).getTarget()=vneedle_131)
}

predicate func_28(Parameter vneedle_131) {
	exists(PointerFieldAccess target_28 |
		target_28.getTarget().getName()="cipher_list13"
		and target_28.getQualifier().(VariableAccess).getTarget()=vneedle_131)
}

from Function func, Parameter vdata_130, Parameter vneedle_131
where
not func_0(vdata_130, vneedle_131)
and not func_1(vdata_130, vneedle_131)
and not func_2(vdata_130, vneedle_131)
and not func_3(vdata_130, vneedle_131)
and not func_4(vdata_130, vneedle_131)
and func_5(vdata_130, vneedle_131)
and func_6(vdata_130, vneedle_131)
and func_7(vdata_130, vneedle_131)
and func_8(vdata_130, vneedle_131)
and func_9(vdata_130, vneedle_131)
and func_10(vdata_130, vneedle_131)
and func_11(vdata_130, vneedle_131)
and func_12(vdata_130, vneedle_131)
and func_13(vdata_130, vneedle_131)
and func_14(vdata_130, vneedle_131)
and func_15(vdata_130, vneedle_131)
and func_16(vdata_130, vneedle_131)
and func_17(vdata_130, vneedle_131)
and func_18(vdata_130, vneedle_131)
and func_19(vdata_130, vneedle_131)
and func_20(vdata_130, vneedle_131)
and vdata_130.getType().hasName("ssl_primary_config *")
and func_21(vdata_130)
and func_22(vdata_130)
and func_23(vdata_130)
and func_24(vdata_130)
and vneedle_131.getType().hasName("ssl_primary_config *")
and func_25(vneedle_131)
and func_26(vneedle_131)
and func_27(vneedle_131)
and func_28(vneedle_131)
and vdata_130.getParentScope+() = func
and vneedle_131.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
