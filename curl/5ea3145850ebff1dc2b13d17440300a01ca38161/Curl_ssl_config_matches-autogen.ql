/**
 * @name curl-5ea3145850ebff1dc2b13d17440300a01ca38161-Curl_ssl_config_matches
 * @id cpp/curl/5ea3145850ebff1dc2b13d17440300a01ca38161/Curl-ssl-config-matches
 * @description curl-5ea3145850ebff1dc2b13d17440300a01ca38161-lib/vtls/vtls.c-Curl_ssl_config_matches CVE-2021-22924
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vneedle_130, Parameter vdata_129) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(LogicalAndExpr).getAnOperand() instanceof LogicalAndExpr
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("blobcmp")
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="issuercert_blob"
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_129
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="issuercert_blob"
		and target_0.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_130
		and target_0.getAnOperand().(FunctionCall).getTarget().hasName("safecmp")
		and target_0.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="CApath"
		and target_0.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_129
		and target_0.getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="CApath"
		and target_0.getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_130)
}

predicate func_1(Parameter vneedle_130, Parameter vdata_129, LogicalAndExpr target_22) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("safecmp")
		and target_1.getArgument(0).(PointerFieldAccess).getTarget().getName()="CAfile"
		and target_1.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_129
		and target_1.getArgument(1).(PointerFieldAccess).getTarget().getName()="CAfile"
		and target_1.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_130
		and target_1.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_22.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vneedle_130, Parameter vdata_129, LogicalAndExpr target_22) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("safecmp")
		and target_2.getArgument(0).(PointerFieldAccess).getTarget().getName()="issuercert"
		and target_2.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_129
		and target_2.getArgument(1).(PointerFieldAccess).getTarget().getName()="issuercert"
		and target_2.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_130
		and target_22.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vneedle_130, Parameter vdata_129, LogicalAndExpr target_22) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("safecmp")
		and target_3.getArgument(0).(PointerFieldAccess).getTarget().getName()="clientcert"
		and target_3.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_129
		and target_3.getArgument(1).(PointerFieldAccess).getTarget().getName()="clientcert"
		and target_3.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_130
		and target_22.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_4(Parameter vneedle_130, Parameter vdata_129, LogicalAndExpr target_22) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("safecmp")
		and target_4.getArgument(0).(PointerFieldAccess).getTarget().getName()="random_file"
		and target_4.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_129
		and target_4.getArgument(1).(PointerFieldAccess).getTarget().getName()="random_file"
		and target_4.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_130
		and target_22.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_5(Parameter vneedle_130, Parameter vdata_129, LogicalAndExpr target_22) {
	exists(FunctionCall target_5 |
		target_5.getTarget().hasName("safecmp")
		and target_5.getArgument(0).(PointerFieldAccess).getTarget().getName()="egdsocket"
		and target_5.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_129
		and target_5.getArgument(1).(PointerFieldAccess).getTarget().getName()="egdsocket"
		and target_5.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_130
		and target_22.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_6(Parameter vneedle_130, Parameter vdata_129, LogicalAndExpr target_6) {
		target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="verifypeer"
		and target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="verifypeer"
		and target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="verifyhost"
		and target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_129
		and target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="verifyhost"
		and target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_130
		and target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="verifystatus"
		and target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_129
		and target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="verifystatus"
		and target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_130
		and target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("blobcmp")
		and target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="cert_blob"
		and target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_129
		and target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="cert_blob"
		and target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_130
		and target_6.getAnOperand().(FunctionCall).getTarget().hasName("blobcmp")
		and target_6.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ca_info_blob"
		and target_6.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_129
		and target_6.getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="ca_info_blob"
		and target_6.getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_130
}

predicate func_7(Parameter vdata_129, PointerFieldAccess target_7) {
		target_7.getTarget().getName()="CApath"
		and target_7.getQualifier().(VariableAccess).getTarget()=vdata_129
		and target_7.getParent().(FunctionCall).getParent().(LogicalAndExpr).getAnOperand() instanceof FunctionCall
}

predicate func_8(Parameter vneedle_130, PointerFieldAccess target_8) {
		target_8.getTarget().getName()="CApath"
		and target_8.getQualifier().(VariableAccess).getTarget()=vneedle_130
		and target_8.getParent().(FunctionCall).getParent().(LogicalAndExpr).getAnOperand() instanceof FunctionCall
}

predicate func_9(Parameter vdata_129, PointerFieldAccess target_9) {
		target_9.getTarget().getName()="CAfile"
		and target_9.getQualifier().(VariableAccess).getTarget()=vdata_129
		and target_9.getParent().(FunctionCall).getParent().(LogicalAndExpr).getAnOperand() instanceof FunctionCall
}

predicate func_10(Parameter vneedle_130, PointerFieldAccess target_10) {
		target_10.getTarget().getName()="CAfile"
		and target_10.getQualifier().(VariableAccess).getTarget()=vneedle_130
		and target_10.getParent().(FunctionCall).getParent().(LogicalAndExpr).getAnOperand() instanceof FunctionCall
}

predicate func_11(Parameter vdata_129, PointerFieldAccess target_11) {
		target_11.getTarget().getName()="clientcert"
		and target_11.getQualifier().(VariableAccess).getTarget()=vdata_129
		and target_11.getParent().(FunctionCall).getParent().(LogicalAndExpr).getAnOperand() instanceof FunctionCall
}

predicate func_12(Parameter vneedle_130, PointerFieldAccess target_12) {
		target_12.getTarget().getName()="clientcert"
		and target_12.getQualifier().(VariableAccess).getTarget()=vneedle_130
		and target_12.getParent().(FunctionCall).getParent().(LogicalAndExpr).getAnOperand() instanceof FunctionCall
}

predicate func_13(Parameter vdata_129, PointerFieldAccess target_13) {
		target_13.getTarget().getName()="random_file"
		and target_13.getQualifier().(VariableAccess).getTarget()=vdata_129
		and target_13.getParent().(FunctionCall).getParent().(LogicalAndExpr).getAnOperand() instanceof FunctionCall
}

predicate func_14(Parameter vneedle_130, PointerFieldAccess target_14) {
		target_14.getTarget().getName()="random_file"
		and target_14.getQualifier().(VariableAccess).getTarget()=vneedle_130
		and target_14.getParent().(FunctionCall).getParent().(LogicalAndExpr).getAnOperand() instanceof FunctionCall
}

predicate func_15(Parameter vdata_129, PointerFieldAccess target_15) {
		target_15.getTarget().getName()="egdsocket"
		and target_15.getQualifier().(VariableAccess).getTarget()=vdata_129
		and target_15.getParent().(FunctionCall).getParent().(LogicalAndExpr).getAnOperand() instanceof FunctionCall
}

predicate func_16(Parameter vneedle_130, PointerFieldAccess target_16) {
		target_16.getTarget().getName()="egdsocket"
		and target_16.getQualifier().(VariableAccess).getTarget()=vneedle_130
		and target_16.getParent().(FunctionCall).getParent().(LogicalAndExpr).getAnOperand() instanceof FunctionCall
}

predicate func_17(Parameter vneedle_130, Parameter vdata_129, FunctionCall target_17) {
		target_17.getTarget().hasName("Curl_safe_strcasecompare")
		and target_17.getArgument(0).(PointerFieldAccess).getTarget().getName()="CApath"
		and target_17.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_129
		and target_17.getArgument(1).(PointerFieldAccess).getTarget().getName()="CApath"
		and target_17.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_130
}

predicate func_18(Parameter vneedle_130, Parameter vdata_129, FunctionCall target_18) {
		target_18.getTarget().hasName("Curl_safe_strcasecompare")
		and target_18.getArgument(0).(PointerFieldAccess).getTarget().getName()="CAfile"
		and target_18.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_129
		and target_18.getArgument(1).(PointerFieldAccess).getTarget().getName()="CAfile"
		and target_18.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_130
}

predicate func_19(Parameter vneedle_130, Parameter vdata_129, FunctionCall target_19) {
		target_19.getTarget().hasName("Curl_safe_strcasecompare")
		and target_19.getArgument(0).(PointerFieldAccess).getTarget().getName()="clientcert"
		and target_19.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_129
		and target_19.getArgument(1).(PointerFieldAccess).getTarget().getName()="clientcert"
		and target_19.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_130
}

predicate func_20(Parameter vneedle_130, Parameter vdata_129, FunctionCall target_20) {
		target_20.getTarget().hasName("Curl_safe_strcasecompare")
		and target_20.getArgument(0).(PointerFieldAccess).getTarget().getName()="random_file"
		and target_20.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_129
		and target_20.getArgument(1).(PointerFieldAccess).getTarget().getName()="random_file"
		and target_20.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_130
}

predicate func_21(Parameter vneedle_130, Parameter vdata_129, FunctionCall target_21) {
		target_21.getTarget().hasName("Curl_safe_strcasecompare")
		and target_21.getArgument(0).(PointerFieldAccess).getTarget().getName()="egdsocket"
		and target_21.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_129
		and target_21.getArgument(1).(PointerFieldAccess).getTarget().getName()="egdsocket"
		and target_21.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_130
}

predicate func_22(Parameter vneedle_130, Parameter vdata_129, LogicalAndExpr target_22) {
		target_22.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand() instanceof FunctionCall
		and target_22.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand() instanceof FunctionCall
		and target_22.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("Curl_safe_strcasecompare")
		and target_22.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="cipher_list"
		and target_22.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_129
		and target_22.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="cipher_list"
		and target_22.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_130
		and target_22.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("Curl_safe_strcasecompare")
		and target_22.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="cipher_list13"
		and target_22.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_129
		and target_22.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="cipher_list13"
		and target_22.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_130
		and target_22.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("Curl_safe_strcasecompare")
		and target_22.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="curves"
		and target_22.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_129
		and target_22.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="curves"
		and target_22.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_130
		and target_22.getAnOperand().(FunctionCall).getTarget().hasName("Curl_safe_strcasecompare")
		and target_22.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="pinned_key"
		and target_22.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_129
		and target_22.getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="pinned_key"
		and target_22.getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vneedle_130
}

from Function func, Parameter vneedle_130, Parameter vdata_129, LogicalAndExpr target_6, PointerFieldAccess target_7, PointerFieldAccess target_8, PointerFieldAccess target_9, PointerFieldAccess target_10, PointerFieldAccess target_11, PointerFieldAccess target_12, PointerFieldAccess target_13, PointerFieldAccess target_14, PointerFieldAccess target_15, PointerFieldAccess target_16, FunctionCall target_17, FunctionCall target_18, FunctionCall target_19, FunctionCall target_20, FunctionCall target_21, LogicalAndExpr target_22
where
not func_0(vneedle_130, vdata_129)
and not func_1(vneedle_130, vdata_129, target_22)
and not func_2(vneedle_130, vdata_129, target_22)
and not func_3(vneedle_130, vdata_129, target_22)
and not func_4(vneedle_130, vdata_129, target_22)
and not func_5(vneedle_130, vdata_129, target_22)
and func_6(vneedle_130, vdata_129, target_6)
and func_7(vdata_129, target_7)
and func_8(vneedle_130, target_8)
and func_9(vdata_129, target_9)
and func_10(vneedle_130, target_10)
and func_11(vdata_129, target_11)
and func_12(vneedle_130, target_12)
and func_13(vdata_129, target_13)
and func_14(vneedle_130, target_14)
and func_15(vdata_129, target_15)
and func_16(vneedle_130, target_16)
and func_17(vneedle_130, vdata_129, target_17)
and func_18(vneedle_130, vdata_129, target_18)
and func_19(vneedle_130, vdata_129, target_19)
and func_20(vneedle_130, vdata_129, target_20)
and func_21(vneedle_130, vdata_129, target_21)
and func_22(vneedle_130, vdata_129, target_22)
and vneedle_130.getType().hasName("ssl_primary_config *")
and vdata_129.getType().hasName("ssl_primary_config *")
and vneedle_130.getFunction() = func
and vdata_129.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
