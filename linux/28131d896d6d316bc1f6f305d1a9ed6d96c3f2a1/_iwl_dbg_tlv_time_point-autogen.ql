/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-_iwl_dbg_tlv_time_point
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/-iwl-dbg-tlv-time-point
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-_iwl_dbg_tlv_time_point CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Parameter vfwrt_1049, Parameter vtp_id_1050, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("list_head *")
		and target_1.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="config_list"
		and target_1.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="time_point"
		and target_1.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dbg"
		and target_1.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="trans"
		and target_1.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfwrt_1049
		and target_1.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vtp_id_1050
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_1))
}

predicate func_2(Parameter vfwrt_1049) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("iwl_dbg_tlv_apply_config")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfwrt_1049
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("list_head *"))
}

predicate func_3(Parameter vfwrt_1049) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(FunctionCall).getTarget().hasName("iwl_dbg_tlv_update_drams")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfwrt_1049)
}

predicate func_7(Parameter vfwrt_1049) {
	exists(PointerFieldAccess target_7 |
		target_7.getTarget().getName()="trans"
		and target_7.getQualifier().(VariableAccess).getTarget()=vfwrt_1049)
}

predicate func_8(Parameter vfwrt_1049) {
	exists(FunctionCall target_8 |
		target_8.getTarget().hasName("iwl_dbg_tlv_init_cfg")
		and target_8.getArgument(0).(VariableAccess).getTarget()=vfwrt_1049)
}

predicate func_9(Parameter vfwrt_1049, Variable vhcmd_list_1054) {
	exists(FunctionCall target_9 |
		target_9.getTarget().hasName("iwl_dbg_tlv_send_hcmds")
		and target_9.getArgument(0).(VariableAccess).getTarget()=vfwrt_1049
		and target_9.getArgument(1).(VariableAccess).getTarget()=vhcmd_list_1054)
}

predicate func_12(Parameter vfwrt_1049, Parameter vtp_id_1050) {
	exists(ArrayExpr target_12 |
		target_12.getArrayBase().(ValueFieldAccess).getTarget().getName()="time_point"
		and target_12.getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dbg"
		and target_12.getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="trans"
		and target_12.getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfwrt_1049
		and target_12.getArrayOffset().(VariableAccess).getTarget()=vtp_id_1050)
}

from Function func, Parameter vfwrt_1049, Parameter vtp_id_1050, Variable vhcmd_list_1054
where
not func_1(vfwrt_1049, vtp_id_1050, func)
and not func_2(vfwrt_1049)
and not func_3(vfwrt_1049)
and vfwrt_1049.getType().hasName("iwl_fw_runtime *")
and func_7(vfwrt_1049)
and func_8(vfwrt_1049)
and func_9(vfwrt_1049, vhcmd_list_1054)
and vtp_id_1050.getType().hasName("iwl_fw_ini_time_point")
and func_12(vfwrt_1049, vtp_id_1050)
and vhcmd_list_1054.getType().hasName("list_head *")
and vfwrt_1049.getParentScope+() = func
and vtp_id_1050.getParentScope+() = func
and vhcmd_list_1054.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
