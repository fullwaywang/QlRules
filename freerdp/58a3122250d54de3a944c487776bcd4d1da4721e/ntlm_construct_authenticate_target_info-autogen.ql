/**
 * @name freerdp-58a3122250d54de3a944c487776bcd4d1da4721e-ntlm_construct_authenticate_target_info
 * @id cpp/freerdp/58a3122250d54de3a944c487776bcd4d1da4721e/ntlm-construct-authenticate-target-info
 * @description freerdp-58a3122250d54de3a944c487776bcd4d1da4721e-winpr/libwinpr/sspi/NTLM/ntlm_av_pairs.c-ntlm_construct_authenticate_target_info CVE-2020-11097
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vAvNbDomainName_469, Variable vcbAvNbDomainName_477, BlockStmt target_23, IfStmt target_24, IfStmt target_25, AddressOfExpr target_26, NotExpr target_27) {
	exists(NotExpr target_0 |
		target_0.getOperand().(FunctionCall).getTarget().hasName("ntlm_av_pair_get_len")
		and target_0.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vAvNbDomainName_469
		and target_0.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcbAvNbDomainName_477
		and target_0.getOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("size_t")
		and target_0.getParent().(IfStmt).getThen()=target_23
		and target_24.getCondition().(VariableAccess).getLocation().isBefore(target_0.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_25.getCondition().(VariableAccess).getLocation())
		and target_26.getOperand().(VariableAccess).getLocation().isBefore(target_0.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_0.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_27.getOperand().(FunctionCall).getArgument(3).(VariableAccess).getLocation()))
}

predicate func_1(VariableAccess target_16, Function func) {
	exists(GotoStmt target_1 |
		target_1.toString() = "goto ..."
		and target_1.getName() ="fail"
		and target_1.getParent().(IfStmt).getCondition()=target_16
		and target_1.getEnclosingFunction() = func)
}

predicate func_3(Variable vAvNbComputerName_470, Variable vcbAvNbComputerName_478, VariableAccess target_28, IfStmt target_29, IfStmt target_30, AddressOfExpr target_31, NotExpr target_32) {
	exists(IfStmt target_3 |
		target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("ntlm_av_pair_get_len")
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vAvNbComputerName_470
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcbAvNbComputerName_478
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("size_t")
		and target_3.getThen().(GotoStmt).toString() = "goto ..."
		and target_3.getThen().(GotoStmt).getName() ="fail"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_28
		and target_29.getCondition().(VariableAccess).getLocation().isBefore(target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_30.getCondition().(VariableAccess).getLocation())
		and target_31.getOperand().(VariableAccess).getLocation().isBefore(target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_32.getOperand().(FunctionCall).getArgument(3).(VariableAccess).getLocation()))
}

predicate func_5(Variable vAvDnsDomainName_471, Variable vcbAvDnsDomainName_479, VariableAccess target_33, IfStmt target_34, IfStmt target_35, AddressOfExpr target_36, NotExpr target_37) {
	exists(IfStmt target_5 |
		target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("ntlm_av_pair_get_len")
		and target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vAvDnsDomainName_471
		and target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcbAvDnsDomainName_479
		and target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("size_t")
		and target_5.getThen().(GotoStmt).toString() = "goto ..."
		and target_5.getThen().(GotoStmt).getName() ="fail"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_5
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_33
		and target_34.getCondition().(VariableAccess).getLocation().isBefore(target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_35.getCondition().(VariableAccess).getLocation())
		and target_36.getOperand().(VariableAccess).getLocation().isBefore(target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_37.getOperand().(FunctionCall).getArgument(3).(VariableAccess).getLocation()))
}

predicate func_7(Variable vAvDnsComputerName_472, Variable vcbAvDnsComputerName_480, VariableAccess target_38, IfStmt target_39, IfStmt target_40, AddressOfExpr target_41, NotExpr target_42) {
	exists(IfStmt target_7 |
		target_7.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("ntlm_av_pair_get_len")
		and target_7.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vAvDnsComputerName_472
		and target_7.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcbAvDnsComputerName_480
		and target_7.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("size_t")
		and target_7.getThen().(GotoStmt).toString() = "goto ..."
		and target_7.getThen().(GotoStmt).getName() ="fail"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_7
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_38
		and target_39.getCondition().(VariableAccess).getLocation().isBefore(target_7.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_7.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_40.getCondition().(VariableAccess).getLocation())
		and target_41.getOperand().(VariableAccess).getLocation().isBefore(target_7.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_7.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_42.getOperand().(FunctionCall).getArgument(3).(VariableAccess).getLocation()))
}

predicate func_9(Variable vAvPairsCount_466, Variable vAvPairsValueLength_467, Variable vAvDnsTreeName_473, Variable vcbAvDnsTreeName_481, ExprStmt target_43, ExprStmt target_44, ExprStmt target_45, ExprStmt target_46, ExprStmt target_47, IfStmt target_48, AddressOfExpr target_49, NotExpr target_50, Function func) {
	exists(IfStmt target_9 |
		target_9.getCondition().(VariableAccess).getTarget()=vAvDnsTreeName_473
		and target_9.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("ntlm_av_pair_get_len")
		and target_9.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vAvDnsTreeName_473
		and target_9.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcbAvDnsTreeName_481
		and target_9.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("size_t")
		and target_9.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(GotoStmt).toString() = "goto ..."
		and target_9.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(GotoStmt).getName() ="fail"
		and target_9.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vAvPairsCount_466
		and target_9.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vAvPairsValueLength_467
		and target_9.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(VariableAccess).getType().hasName("size_t")
		and (func.getEntryPoint().(BlockStmt).getStmt(33)=target_9 or func.getEntryPoint().(BlockStmt).getStmt(33).getFollowingStmt()=target_9)
		and target_43.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_9.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation())
		and target_9.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_44.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation())
		and target_45.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_9.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation())
		and target_9.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_46.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation())
		and target_47.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_9.getCondition().(VariableAccess).getLocation())
		and target_9.getCondition().(VariableAccess).getLocation().isBefore(target_48.getCondition().(VariableAccess).getLocation())
		and target_49.getOperand().(VariableAccess).getLocation().isBefore(target_9.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_9.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_50.getOperand().(FunctionCall).getArgument(3).(VariableAccess).getLocation()))
}

/*predicate func_10(Variable vAvDnsTreeName_473, Variable vcbAvDnsTreeName_481, VariableAccess target_16, IfStmt target_51, IfStmt target_48, AddressOfExpr target_49, NotExpr target_50) {
	exists(IfStmt target_10 |
		target_10.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("ntlm_av_pair_get_len")
		and target_10.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vAvDnsTreeName_473
		and target_10.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcbAvDnsTreeName_481
		and target_10.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("size_t")
		and target_10.getThen().(GotoStmt).toString() = "goto ..."
		and target_10.getThen().(GotoStmt).getName() ="fail"
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_10
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_16
		and target_51.getCondition().(VariableAccess).getLocation().isBefore(target_10.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_10.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_48.getCondition().(VariableAccess).getLocation())
		and target_49.getOperand().(VariableAccess).getLocation().isBefore(target_10.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_10.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_50.getOperand().(FunctionCall).getArgument(3).(VariableAccess).getLocation()))
}

*/
predicate func_12(Variable vAvNbDomainName_469, VariableAccess target_12) {
		target_12.getTarget()=vAvNbDomainName_469
		and target_12.getParent().(FunctionCall).getParent().(AssignAddExpr).getRValue() instanceof FunctionCall
}

predicate func_13(Variable vAvNbComputerName_470, VariableAccess target_13) {
		target_13.getTarget()=vAvNbComputerName_470
		and target_13.getParent().(FunctionCall).getParent().(AssignAddExpr).getRValue() instanceof FunctionCall
}

predicate func_14(Variable vAvDnsDomainName_471, VariableAccess target_14) {
		target_14.getTarget()=vAvDnsDomainName_471
		and target_14.getParent().(FunctionCall).getParent().(AssignAddExpr).getRValue() instanceof FunctionCall
}

predicate func_15(Variable vAvDnsComputerName_472, VariableAccess target_15) {
		target_15.getTarget()=vAvDnsComputerName_472
		and target_15.getParent().(FunctionCall).getParent().(AssignAddExpr).getRValue() instanceof FunctionCall
}

predicate func_16(Variable vAvDnsTreeName_473, BlockStmt target_23, VariableAccess target_16) {
		target_16.getTarget()=vAvDnsTreeName_473
		and target_16.getParent().(IfStmt).getThen()=target_23
}

predicate func_17(Variable vAvDnsTreeName_473, VariableAccess target_17) {
		target_17.getTarget()=vAvDnsTreeName_473
		and target_17.getParent().(FunctionCall).getParent().(AssignAddExpr).getRValue() instanceof FunctionCall
}

predicate func_18(Variable vAvNbDomainName_469, FunctionCall target_18) {
		target_18.getTarget().hasName("ntlm_av_pair_get_len")
		and target_18.getArgument(0).(VariableAccess).getTarget()=vAvNbDomainName_469
}

predicate func_19(Variable vAvNbComputerName_470, FunctionCall target_19) {
		target_19.getTarget().hasName("ntlm_av_pair_get_len")
		and target_19.getArgument(0).(VariableAccess).getTarget()=vAvNbComputerName_470
}

predicate func_20(Variable vAvDnsDomainName_471, FunctionCall target_20) {
		target_20.getTarget().hasName("ntlm_av_pair_get_len")
		and target_20.getArgument(0).(VariableAccess).getTarget()=vAvDnsDomainName_471
}

predicate func_21(Variable vAvDnsComputerName_472, FunctionCall target_21) {
		target_21.getTarget().hasName("ntlm_av_pair_get_len")
		and target_21.getArgument(0).(VariableAccess).getTarget()=vAvDnsComputerName_472
}

predicate func_22(Variable vAvDnsTreeName_473, FunctionCall target_22) {
		target_22.getTarget().hasName("ntlm_av_pair_get_len")
		and target_22.getArgument(0).(VariableAccess).getTarget()=vAvDnsTreeName_473
}

predicate func_23(Variable vAvPairsCount_466, Variable vAvPairsValueLength_467, BlockStmt target_23) {
		target_23.getStmt(0).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vAvPairsCount_466
		and target_23.getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vAvPairsValueLength_467
		and target_23.getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getRValue() instanceof FunctionCall
}

predicate func_24(Variable vAvPairsCount_466, Variable vAvPairsValueLength_467, Variable vAvNbDomainName_469, IfStmt target_24) {
		target_24.getCondition().(VariableAccess).getTarget()=vAvNbDomainName_469
		and target_24.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vAvPairsCount_466
		and target_24.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vAvPairsValueLength_467
		and target_24.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getRValue() instanceof FunctionCall
}

predicate func_25(Variable vAvNbDomainName_469, Variable vcbAvNbDomainName_477, IfStmt target_25) {
		target_25.getCondition().(VariableAccess).getTarget()=vAvNbDomainName_469
		and target_25.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("ntlm_av_pair_add_copy")
		and target_25.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vAvNbDomainName_469
		and target_25.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vcbAvNbDomainName_477
		and target_25.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(GotoStmt).toString() = "goto ..."
		and target_25.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(GotoStmt).getName() ="fail"
}

predicate func_26(Variable vcbAvNbDomainName_477, AddressOfExpr target_26) {
		target_26.getOperand().(VariableAccess).getTarget()=vcbAvNbDomainName_477
}

predicate func_27(Variable vAvNbDomainName_469, Variable vcbAvNbDomainName_477, NotExpr target_27) {
		target_27.getOperand().(FunctionCall).getTarget().hasName("ntlm_av_pair_add_copy")
		and target_27.getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vAvNbDomainName_469
		and target_27.getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vcbAvNbDomainName_477
}

predicate func_28(Variable vAvNbComputerName_470, VariableAccess target_28) {
		target_28.getTarget()=vAvNbComputerName_470
}

predicate func_29(Variable vAvPairsCount_466, Variable vAvPairsValueLength_467, Variable vAvNbComputerName_470, IfStmt target_29) {
		target_29.getCondition().(VariableAccess).getTarget()=vAvNbComputerName_470
		and target_29.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vAvPairsCount_466
		and target_29.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vAvPairsValueLength_467
		and target_29.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getRValue() instanceof FunctionCall
}

predicate func_30(Variable vAvNbComputerName_470, Variable vcbAvNbComputerName_478, IfStmt target_30) {
		target_30.getCondition().(VariableAccess).getTarget()=vAvNbComputerName_470
		and target_30.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("ntlm_av_pair_add_copy")
		and target_30.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vAvNbComputerName_470
		and target_30.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vcbAvNbComputerName_478
		and target_30.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(GotoStmt).toString() = "goto ..."
		and target_30.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(GotoStmt).getName() ="fail"
}

predicate func_31(Variable vcbAvNbComputerName_478, AddressOfExpr target_31) {
		target_31.getOperand().(VariableAccess).getTarget()=vcbAvNbComputerName_478
}

predicate func_32(Variable vAvNbComputerName_470, Variable vcbAvNbComputerName_478, NotExpr target_32) {
		target_32.getOperand().(FunctionCall).getTarget().hasName("ntlm_av_pair_add_copy")
		and target_32.getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vAvNbComputerName_470
		and target_32.getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vcbAvNbComputerName_478
}

predicate func_33(Variable vAvDnsDomainName_471, VariableAccess target_33) {
		target_33.getTarget()=vAvDnsDomainName_471
}

predicate func_34(Variable vAvPairsCount_466, Variable vAvPairsValueLength_467, Variable vAvDnsDomainName_471, IfStmt target_34) {
		target_34.getCondition().(VariableAccess).getTarget()=vAvDnsDomainName_471
		and target_34.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vAvPairsCount_466
		and target_34.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vAvPairsValueLength_467
		and target_34.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getRValue() instanceof FunctionCall
}

predicate func_35(Variable vAvDnsDomainName_471, Variable vcbAvDnsDomainName_479, IfStmt target_35) {
		target_35.getCondition().(VariableAccess).getTarget()=vAvDnsDomainName_471
		and target_35.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("ntlm_av_pair_add_copy")
		and target_35.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vAvDnsDomainName_471
		and target_35.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vcbAvDnsDomainName_479
		and target_35.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(GotoStmt).toString() = "goto ..."
		and target_35.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(GotoStmt).getName() ="fail"
}

predicate func_36(Variable vcbAvDnsDomainName_479, AddressOfExpr target_36) {
		target_36.getOperand().(VariableAccess).getTarget()=vcbAvDnsDomainName_479
}

predicate func_37(Variable vAvDnsDomainName_471, Variable vcbAvDnsDomainName_479, NotExpr target_37) {
		target_37.getOperand().(FunctionCall).getTarget().hasName("ntlm_av_pair_add_copy")
		and target_37.getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vAvDnsDomainName_471
		and target_37.getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vcbAvDnsDomainName_479
}

predicate func_38(Variable vAvDnsComputerName_472, VariableAccess target_38) {
		target_38.getTarget()=vAvDnsComputerName_472
}

predicate func_39(Variable vAvPairsCount_466, Variable vAvPairsValueLength_467, Variable vAvDnsComputerName_472, IfStmt target_39) {
		target_39.getCondition().(VariableAccess).getTarget()=vAvDnsComputerName_472
		and target_39.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vAvPairsCount_466
		and target_39.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vAvPairsValueLength_467
		and target_39.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getRValue() instanceof FunctionCall
}

predicate func_40(Variable vAvDnsComputerName_472, Variable vcbAvDnsComputerName_480, IfStmt target_40) {
		target_40.getCondition().(VariableAccess).getTarget()=vAvDnsComputerName_472
		and target_40.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("ntlm_av_pair_add_copy")
		and target_40.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vAvDnsComputerName_472
		and target_40.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vcbAvDnsComputerName_480
		and target_40.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(GotoStmt).toString() = "goto ..."
		and target_40.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(GotoStmt).getName() ="fail"
}

predicate func_41(Variable vcbAvDnsComputerName_480, AddressOfExpr target_41) {
		target_41.getOperand().(VariableAccess).getTarget()=vcbAvDnsComputerName_480
}

predicate func_42(Variable vAvDnsComputerName_472, Variable vcbAvDnsComputerName_480, NotExpr target_42) {
		target_42.getOperand().(FunctionCall).getTarget().hasName("ntlm_av_pair_add_copy")
		and target_42.getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vAvDnsComputerName_472
		and target_42.getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vcbAvDnsComputerName_480
}

predicate func_43(Variable vAvPairsCount_466, ExprStmt target_43) {
		target_43.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vAvPairsCount_466
}

predicate func_44(Variable vAvPairsCount_466, ExprStmt target_44) {
		target_44.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vAvPairsCount_466
}

predicate func_45(Variable vAvPairsValueLength_467, ExprStmt target_45) {
		target_45.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vAvPairsValueLength_467
		and target_45.getExpr().(AssignAddExpr).getRValue() instanceof FunctionCall
}

predicate func_46(Variable vAvPairsValueLength_467, ExprStmt target_46) {
		target_46.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vAvPairsValueLength_467
		and target_46.getExpr().(AssignAddExpr).getRValue().(Literal).getValue()="8"
}

predicate func_47(Variable vAvDnsTreeName_473, Variable vcbAvDnsTreeName_481, ExprStmt target_47) {
		target_47.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vAvDnsTreeName_473
		and target_47.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ntlm_av_pair_get")
		and target_47.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vcbAvDnsTreeName_481
}

predicate func_48(Variable vAvDnsTreeName_473, Variable vcbAvDnsTreeName_481, IfStmt target_48) {
		target_48.getCondition().(VariableAccess).getTarget()=vAvDnsTreeName_473
		and target_48.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("ntlm_av_pair_add_copy")
		and target_48.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vAvDnsTreeName_473
		and target_48.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vcbAvDnsTreeName_481
		and target_48.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(GotoStmt).toString() = "goto ..."
		and target_48.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(GotoStmt).getName() ="fail"
}

predicate func_49(Variable vcbAvDnsTreeName_481, AddressOfExpr target_49) {
		target_49.getOperand().(VariableAccess).getTarget()=vcbAvDnsTreeName_481
}

predicate func_50(Variable vAvDnsTreeName_473, Variable vcbAvDnsTreeName_481, NotExpr target_50) {
		target_50.getOperand().(FunctionCall).getTarget().hasName("ntlm_av_pair_add_copy")
		and target_50.getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vAvDnsTreeName_473
		and target_50.getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vcbAvDnsTreeName_481
}

predicate func_51(Variable vAvPairsCount_466, Variable vAvPairsValueLength_467, Variable vAvDnsTreeName_473, IfStmt target_51) {
		target_51.getCondition().(VariableAccess).getTarget()=vAvDnsTreeName_473
		and target_51.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vAvPairsCount_466
		and target_51.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vAvPairsValueLength_467
		and target_51.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getRValue() instanceof FunctionCall
}

from Function func, Variable vAvPairsCount_466, Variable vAvPairsValueLength_467, Variable vAvNbDomainName_469, Variable vAvNbComputerName_470, Variable vAvDnsDomainName_471, Variable vAvDnsComputerName_472, Variable vAvDnsTreeName_473, Variable vcbAvNbDomainName_477, Variable vcbAvNbComputerName_478, Variable vcbAvDnsDomainName_479, Variable vcbAvDnsComputerName_480, Variable vcbAvDnsTreeName_481, VariableAccess target_12, VariableAccess target_13, VariableAccess target_14, VariableAccess target_15, VariableAccess target_16, VariableAccess target_17, FunctionCall target_18, FunctionCall target_19, FunctionCall target_20, FunctionCall target_21, FunctionCall target_22, BlockStmt target_23, IfStmt target_24, IfStmt target_25, AddressOfExpr target_26, NotExpr target_27, VariableAccess target_28, IfStmt target_29, IfStmt target_30, AddressOfExpr target_31, NotExpr target_32, VariableAccess target_33, IfStmt target_34, IfStmt target_35, AddressOfExpr target_36, NotExpr target_37, VariableAccess target_38, IfStmt target_39, IfStmt target_40, AddressOfExpr target_41, NotExpr target_42, ExprStmt target_43, ExprStmt target_44, ExprStmt target_45, ExprStmt target_46, ExprStmt target_47, IfStmt target_48, AddressOfExpr target_49, NotExpr target_50, IfStmt target_51
where
not func_0(vAvNbDomainName_469, vcbAvNbDomainName_477, target_23, target_24, target_25, target_26, target_27)
and not func_1(target_16, func)
and not func_3(vAvNbComputerName_470, vcbAvNbComputerName_478, target_28, target_29, target_30, target_31, target_32)
and not func_5(vAvDnsDomainName_471, vcbAvDnsDomainName_479, target_33, target_34, target_35, target_36, target_37)
and not func_7(vAvDnsComputerName_472, vcbAvDnsComputerName_480, target_38, target_39, target_40, target_41, target_42)
and not func_9(vAvPairsCount_466, vAvPairsValueLength_467, vAvDnsTreeName_473, vcbAvDnsTreeName_481, target_43, target_44, target_45, target_46, target_47, target_48, target_49, target_50, func)
and func_12(vAvNbDomainName_469, target_12)
and func_13(vAvNbComputerName_470, target_13)
and func_14(vAvDnsDomainName_471, target_14)
and func_15(vAvDnsComputerName_472, target_15)
and func_16(vAvDnsTreeName_473, target_23, target_16)
and func_17(vAvDnsTreeName_473, target_17)
and func_18(vAvNbDomainName_469, target_18)
and func_19(vAvNbComputerName_470, target_19)
and func_20(vAvDnsDomainName_471, target_20)
and func_21(vAvDnsComputerName_472, target_21)
and func_22(vAvDnsTreeName_473, target_22)
and func_23(vAvPairsCount_466, vAvPairsValueLength_467, target_23)
and func_24(vAvPairsCount_466, vAvPairsValueLength_467, vAvNbDomainName_469, target_24)
and func_25(vAvNbDomainName_469, vcbAvNbDomainName_477, target_25)
and func_26(vcbAvNbDomainName_477, target_26)
and func_27(vAvNbDomainName_469, vcbAvNbDomainName_477, target_27)
and func_28(vAvNbComputerName_470, target_28)
and func_29(vAvPairsCount_466, vAvPairsValueLength_467, vAvNbComputerName_470, target_29)
and func_30(vAvNbComputerName_470, vcbAvNbComputerName_478, target_30)
and func_31(vcbAvNbComputerName_478, target_31)
and func_32(vAvNbComputerName_470, vcbAvNbComputerName_478, target_32)
and func_33(vAvDnsDomainName_471, target_33)
and func_34(vAvPairsCount_466, vAvPairsValueLength_467, vAvDnsDomainName_471, target_34)
and func_35(vAvDnsDomainName_471, vcbAvDnsDomainName_479, target_35)
and func_36(vcbAvDnsDomainName_479, target_36)
and func_37(vAvDnsDomainName_471, vcbAvDnsDomainName_479, target_37)
and func_38(vAvDnsComputerName_472, target_38)
and func_39(vAvPairsCount_466, vAvPairsValueLength_467, vAvDnsComputerName_472, target_39)
and func_40(vAvDnsComputerName_472, vcbAvDnsComputerName_480, target_40)
and func_41(vcbAvDnsComputerName_480, target_41)
and func_42(vAvDnsComputerName_472, vcbAvDnsComputerName_480, target_42)
and func_43(vAvPairsCount_466, target_43)
and func_44(vAvPairsCount_466, target_44)
and func_45(vAvPairsValueLength_467, target_45)
and func_46(vAvPairsValueLength_467, target_46)
and func_47(vAvDnsTreeName_473, vcbAvDnsTreeName_481, target_47)
and func_48(vAvDnsTreeName_473, vcbAvDnsTreeName_481, target_48)
and func_49(vcbAvDnsTreeName_481, target_49)
and func_50(vAvDnsTreeName_473, vcbAvDnsTreeName_481, target_50)
and func_51(vAvPairsCount_466, vAvPairsValueLength_467, vAvDnsTreeName_473, target_51)
and vAvPairsCount_466.getType().hasName("ULONG")
and vAvPairsValueLength_467.getType().hasName("ULONG")
and vAvNbDomainName_469.getType().hasName("NTLM_AV_PAIR *")
and vAvNbComputerName_470.getType().hasName("NTLM_AV_PAIR *")
and vAvDnsDomainName_471.getType().hasName("NTLM_AV_PAIR *")
and vAvDnsComputerName_472.getType().hasName("NTLM_AV_PAIR *")
and vAvDnsTreeName_473.getType().hasName("NTLM_AV_PAIR *")
and vcbAvNbDomainName_477.getType().hasName("size_t")
and vcbAvNbComputerName_478.getType().hasName("size_t")
and vcbAvDnsDomainName_479.getType().hasName("size_t")
and vcbAvDnsComputerName_480.getType().hasName("size_t")
and vcbAvDnsTreeName_481.getType().hasName("size_t")
and vAvPairsCount_466.getParentScope+() = func
and vAvPairsValueLength_467.getParentScope+() = func
and vAvNbDomainName_469.getParentScope+() = func
and vAvNbComputerName_470.getParentScope+() = func
and vAvDnsDomainName_471.getParentScope+() = func
and vAvDnsComputerName_472.getParentScope+() = func
and vAvDnsTreeName_473.getParentScope+() = func
and vcbAvNbDomainName_477.getParentScope+() = func
and vcbAvNbComputerName_478.getParentScope+() = func
and vcbAvDnsDomainName_479.getParentScope+() = func
and vcbAvDnsComputerName_480.getParentScope+() = func
and vcbAvDnsTreeName_481.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
