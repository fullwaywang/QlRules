/**
 * @name linux-e04480920d1eec9c061841399aa6f35b6f987d8b-hci_unregister_dev
 * @id cpp/linux/e04480920d1eec9c061841399aa6f35b6f987d8b/hci_unregister_dev
 * @description linux-e04480920d1eec9c061841399aa6f35b6f987d8b-hci_unregister_dev CVE-2021-3573
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(DeclStmt target_0 |
		func.getEntryPoint().(BlockStmt).getAStmt()=target_0)
}

predicate func_1(Variable vid_3999, Parameter vhdev_3997, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vid_3999
		and target_1.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="id"
		and target_1.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhdev_3997
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1)
}

predicate func_2(Parameter vhdev_3997, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("debugfs_remove")
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="debugfs"
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhdev_3997
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2)
}

predicate func_3(Parameter vhdev_3997, Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(FunctionCall).getTarget().hasName("kfree_const")
		and target_3.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="hw_info"
		and target_3.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhdev_3997
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3)
}

predicate func_4(Parameter vhdev_3997, Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(FunctionCall).getTarget().hasName("kfree_const")
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="fw_info"
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhdev_3997
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4)
}

predicate func_5(Parameter vhdev_3997, Function func) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(FunctionCall).getTarget().hasName("destroy_workqueue")
		and target_5.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="workqueue"
		and target_5.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhdev_3997
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_5)
}

predicate func_6(Parameter vhdev_3997, Function func) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(FunctionCall).getTarget().hasName("destroy_workqueue")
		and target_6.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="req_workqueue"
		and target_6.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhdev_3997
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_6)
}

predicate func_7(Parameter vhdev_3997, Function func) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(FunctionCall).getTarget().hasName("mutex_lock_nested")
		and target_7.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="lock"
		and target_7.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhdev_3997
		and target_7.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_7)
}

predicate func_8(Parameter vhdev_3997, Function func) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(FunctionCall).getTarget().hasName("hci_bdaddr_list_clear")
		and target_8.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="reject_list"
		and target_8.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhdev_3997
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_8)
}

predicate func_9(Parameter vhdev_3997, Function func) {
	exists(ExprStmt target_9 |
		target_9.getExpr().(FunctionCall).getTarget().hasName("hci_bdaddr_list_clear")
		and target_9.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="accept_list"
		and target_9.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhdev_3997
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_9)
}

predicate func_10(Parameter vhdev_3997, Function func) {
	exists(ExprStmt target_10 |
		target_10.getExpr().(FunctionCall).getTarget().hasName("hci_uuids_clear")
		and target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vhdev_3997
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_10)
}

predicate func_11(Parameter vhdev_3997, Function func) {
	exists(ExprStmt target_11 |
		target_11.getExpr().(FunctionCall).getTarget().hasName("hci_link_keys_clear")
		and target_11.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vhdev_3997
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_11)
}

predicate func_12(Parameter vhdev_3997, Function func) {
	exists(ExprStmt target_12 |
		target_12.getExpr().(FunctionCall).getTarget().hasName("hci_smp_ltks_clear")
		and target_12.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vhdev_3997
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_12)
}

predicate func_13(Parameter vhdev_3997, Function func) {
	exists(ExprStmt target_13 |
		target_13.getExpr().(FunctionCall).getTarget().hasName("hci_smp_irks_clear")
		and target_13.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vhdev_3997
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_13)
}

predicate func_14(Parameter vhdev_3997, Function func) {
	exists(ExprStmt target_14 |
		target_14.getExpr().(FunctionCall).getTarget().hasName("hci_remote_oob_data_clear")
		and target_14.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vhdev_3997
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_14)
}

predicate func_15(Parameter vhdev_3997, Function func) {
	exists(ExprStmt target_15 |
		target_15.getExpr().(FunctionCall).getTarget().hasName("hci_adv_instances_clear")
		and target_15.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vhdev_3997
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_15)
}

predicate func_16(Parameter vhdev_3997, Function func) {
	exists(ExprStmt target_16 |
		target_16.getExpr().(FunctionCall).getTarget().hasName("hci_adv_monitors_clear")
		and target_16.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vhdev_3997
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_16)
}

predicate func_17(Parameter vhdev_3997, Function func) {
	exists(ExprStmt target_17 |
		target_17.getExpr().(FunctionCall).getTarget().hasName("hci_bdaddr_list_clear")
		and target_17.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="le_accept_list"
		and target_17.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhdev_3997
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_17)
}

predicate func_18(Parameter vhdev_3997, Function func) {
	exists(ExprStmt target_18 |
		target_18.getExpr().(FunctionCall).getTarget().hasName("hci_bdaddr_list_clear")
		and target_18.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="le_resolv_list"
		and target_18.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhdev_3997
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_18)
}

predicate func_19(Parameter vhdev_3997, Function func) {
	exists(ExprStmt target_19 |
		target_19.getExpr().(FunctionCall).getTarget().hasName("hci_conn_params_clear_all")
		and target_19.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vhdev_3997
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_19)
}

predicate func_20(Parameter vhdev_3997, Function func) {
	exists(ExprStmt target_20 |
		target_20.getExpr().(FunctionCall).getTarget().hasName("hci_discovery_filter_clear")
		and target_20.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vhdev_3997
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_20)
}

predicate func_21(Parameter vhdev_3997, Function func) {
	exists(ExprStmt target_21 |
		target_21.getExpr().(FunctionCall).getTarget().hasName("hci_blocked_keys_clear")
		and target_21.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vhdev_3997
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_21)
}

predicate func_22(Parameter vhdev_3997, Function func) {
	exists(ExprStmt target_22 |
		target_22.getExpr().(FunctionCall).getTarget().hasName("mutex_unlock")
		and target_22.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="lock"
		and target_22.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhdev_3997
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_22)
}

predicate func_23(Variable vid_3999, Variable vhci_index_ida, Function func) {
	exists(ExprStmt target_23 |
		target_23.getExpr().(FunctionCall).getTarget().hasName("ida_free")
		and target_23.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vhci_index_ida
		and target_23.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vid_3999
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_23)
}

from Function func, Variable vid_3999, Variable vhci_index_ida, Parameter vhdev_3997
where
func_0(func)
and func_1(vid_3999, vhdev_3997, func)
and func_2(vhdev_3997, func)
and func_3(vhdev_3997, func)
and func_4(vhdev_3997, func)
and func_5(vhdev_3997, func)
and func_6(vhdev_3997, func)
and func_7(vhdev_3997, func)
and func_8(vhdev_3997, func)
and func_9(vhdev_3997, func)
and func_10(vhdev_3997, func)
and func_11(vhdev_3997, func)
and func_12(vhdev_3997, func)
and func_13(vhdev_3997, func)
and func_14(vhdev_3997, func)
and func_15(vhdev_3997, func)
and func_16(vhdev_3997, func)
and func_17(vhdev_3997, func)
and func_18(vhdev_3997, func)
and func_19(vhdev_3997, func)
and func_20(vhdev_3997, func)
and func_21(vhdev_3997, func)
and func_22(vhdev_3997, func)
and func_23(vid_3999, vhci_index_ida, func)
and vid_3999.getType().hasName("int")
and vhci_index_ida.getType().hasName("ida")
and vhdev_3997.getType().hasName("hci_dev *")
and vid_3999.getParentScope+() = func
and not vhci_index_ida.getParentScope+() = func
and vhdev_3997.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
