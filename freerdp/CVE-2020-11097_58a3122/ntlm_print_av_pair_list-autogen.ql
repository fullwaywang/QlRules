/**
 * @name freerdp-58a3122250d54de3a944c487776bcd4d1da4721e-ntlm_print_av_pair_list
 * @id cpp/freerdp/58a3122250d54de3a944c487776bcd4d1da4721e/ntlm-print-av-pair-list
 * @description freerdp-58a3122250d54de3a944c487776bcd4d1da4721e-winpr/libwinpr/sspi/NTLM/ntlm_av_pairs.c-ntlm_print_av_pair_list CVE-2020-11097
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcbAvPair_105, Variable vpAvPair_106, NotExpr target_15, ArrayExpr target_11) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(VariableAccess).getTarget()=vpAvPair_106
		and target_0.getAnOperand().(FunctionCall).getTarget().hasName("ntlm_av_pair_get_id")
		and target_0.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpAvPair_106
		and target_0.getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcbAvPair_105
		and target_0.getAnOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("UINT16")
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vpAvPair_106
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand() instanceof FunctionCall
		and target_15.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_0.getAnOperand().(VariableAccess).getLocation().isBefore(target_11.getArrayOffset().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Variable vcbAvPair_105, Variable vpAvPair_106, AddressOfExpr target_16, LogicalAndExpr target_17) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("ntlm_av_pair_get_len")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vpAvPair_106
		and target_2.getArgument(1).(VariableAccess).getTarget()=vcbAvPair_105
		and target_2.getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("size_t")
		and target_2.getArgument(1).(VariableAccess).getLocation().isBefore(target_16.getOperand().(VariableAccess).getLocation())
		and target_17.getAnOperand().(VariableAccess).getLocation().isBefore(target_2.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_3(Function func) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("get_av_pair_string")
		and target_3.getArgument(0).(VariableAccess).getType().hasName("UINT16")
		and target_3.getEnclosingFunction() = func)
}

predicate func_5(Variable vpAvPair_106, FunctionCall target_13, FunctionCall target_14) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(FunctionCall).getTarget().hasName("winpr_HexDump")
		and target_5.getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="com.winpr.sspi.NTLM"
		and target_5.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="2"
		and target_5.getExpr().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("ntlm_av_pair_get_value_pointer")
		and target_5.getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpAvPair_106
		and target_5.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getType().hasName("size_t")
		and target_13.getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_5.getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_14.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_7(Variable vpAvPair_106, VariableAccess target_7) {
		target_7.getTarget()=vpAvPair_106
		and target_7.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand() instanceof FunctionCall
}

predicate func_8(Variable vpAvPair_106, VariableAccess target_8) {
		target_8.getTarget()=vpAvPair_106
		and target_8.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand() instanceof FunctionCall
}

predicate func_9(Variable vpAvPair_106, VariableAccess target_9) {
		target_9.getTarget()=vpAvPair_106
		and target_9.getParent().(FunctionCall).getParent().(ArrayExpr).getArrayOffset() instanceof FunctionCall
}

predicate func_10(Variable vpAvPair_106, ArrayExpr target_11, FunctionCall target_10) {
		target_10.getTarget().hasName("ntlm_av_pair_get_id")
		and target_10.getArgument(0).(VariableAccess).getTarget()=vpAvPair_106
		and target_10.getArgument(0).(VariableAccess).getLocation().isBefore(target_11.getArrayOffset().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_11(Variable vAV_PAIR_STRINGS, Variable vpAvPair_106, ArrayExpr target_11) {
		target_11.getArrayBase().(VariableAccess).getTarget()=vAV_PAIR_STRINGS
		and target_11.getArrayOffset().(FunctionCall).getTarget().hasName("ntlm_av_pair_get_id")
		and target_11.getArrayOffset().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpAvPair_106
		and target_11.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("WLog_PrintMessage")
		and target_11.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_11.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="2"
		and target_11.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_11.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof StringLiteral
		and target_11.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="\t%s AvId: %u AvLen: %u"
		and target_11.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(8).(FunctionCall).getTarget().hasName("ntlm_av_pair_get_id")
		and target_11.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(8).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpAvPair_106
		and target_11.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(9).(FunctionCall).getTarget().hasName("ntlm_av_pair_get_len")
		and target_11.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(9).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpAvPair_106
}

/*predicate func_12(Variable vpAvPair_106, FunctionCall target_13, FunctionCall target_12) {
		target_12.getTarget().hasName("ntlm_av_pair_get_id")
		and target_12.getArgument(0).(VariableAccess).getTarget()=vpAvPair_106
		and target_12.getArgument(0).(VariableAccess).getLocation().isBefore(target_13.getArgument(0).(VariableAccess).getLocation())
}

*/
predicate func_13(Variable vpAvPair_106, FunctionCall target_13) {
		target_13.getTarget().hasName("ntlm_av_pair_get_len")
		and target_13.getArgument(0).(VariableAccess).getTarget()=vpAvPair_106
}

predicate func_14(Variable vpAvPair_106, FunctionCall target_14) {
		target_14.getTarget().hasName("ntlm_av_pair_get_len")
		and target_14.getArgument(0).(VariableAccess).getTarget()=vpAvPair_106
}

predicate func_15(Variable vcbAvPair_105, Variable vpAvPair_106, NotExpr target_15) {
		target_15.getOperand().(FunctionCall).getTarget().hasName("ntlm_av_pair_check")
		and target_15.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpAvPair_106
		and target_15.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcbAvPair_105
}

predicate func_16(Variable vcbAvPair_105, AddressOfExpr target_16) {
		target_16.getOperand().(VariableAccess).getTarget()=vcbAvPair_105
}

predicate func_17(Variable vpAvPair_106, LogicalAndExpr target_17) {
		target_17.getAnOperand().(VariableAccess).getTarget()=vpAvPair_106
		and target_17.getAnOperand().(EqualityOperation).getAnOperand() instanceof FunctionCall
}

from Function func, Variable vAV_PAIR_STRINGS, Variable vcbAvPair_105, Variable vpAvPair_106, VariableAccess target_7, VariableAccess target_8, VariableAccess target_9, FunctionCall target_10, ArrayExpr target_11, FunctionCall target_13, FunctionCall target_14, NotExpr target_15, AddressOfExpr target_16, LogicalAndExpr target_17
where
not func_0(vcbAvPair_105, vpAvPair_106, target_15, target_11)
and not func_2(vcbAvPair_105, vpAvPair_106, target_16, target_17)
and not func_3(func)
and not func_5(vpAvPair_106, target_13, target_14)
and func_7(vpAvPair_106, target_7)
and func_8(vpAvPair_106, target_8)
and func_9(vpAvPair_106, target_9)
and func_10(vpAvPair_106, target_11, target_10)
and func_11(vAV_PAIR_STRINGS, vpAvPair_106, target_11)
and func_13(vpAvPair_106, target_13)
and func_14(vpAvPair_106, target_14)
and func_15(vcbAvPair_105, vpAvPair_106, target_15)
and func_16(vcbAvPair_105, target_16)
and func_17(vpAvPair_106, target_17)
and vAV_PAIR_STRINGS.getType() instanceof ArrayType
and vcbAvPair_105.getType().hasName("size_t")
and vpAvPair_106.getType().hasName("NTLM_AV_PAIR *")
and not vAV_PAIR_STRINGS.getParentScope+() = func
and vcbAvPair_105.getParentScope+() = func
and vpAvPair_106.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
