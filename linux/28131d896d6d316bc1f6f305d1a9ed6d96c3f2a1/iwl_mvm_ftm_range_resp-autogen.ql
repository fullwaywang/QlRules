/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_mvm_ftm_range_resp
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/iwl-mvm-ftm-range-resp
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_mvm_ftm_range_resp CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vfw_resp_v8_1166, Variable vi_1167, Variable vnotif_ver_1171, Variable vfw_ap_1204, Parameter vmvm_1159) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GEExpr or target_0 instanceof LEExpr)
		and target_0.getGreaterOperand().(VariableAccess).getTarget()=vnotif_ver_1171
		and target_0.getLesserOperand() instanceof Literal
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfw_ap_1204
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="ap"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfw_resp_v8_1166
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_1167
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("iwl_mvm_ftm_pasn_update_pn")
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmvm_1159
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vfw_ap_1204)
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="8"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Variable vfw_resp_v8_1166, Variable vi_1167, Variable vnotif_ver_1171, Variable vfw_ap_1204, Parameter vmvm_1159) {
	exists(EqualityOperation target_3 |
		target_3.getAnOperand().(VariableAccess).getTarget()=vnotif_ver_1171
		and target_3.getAnOperand() instanceof Literal
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfw_ap_1204
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="ap"
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfw_resp_v8_1166
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_1167
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("iwl_mvm_ftm_pasn_update_pn")
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmvm_1159
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vfw_ap_1204)
}

from Function func, Variable vfw_resp_v8_1166, Variable vi_1167, Variable vnotif_ver_1171, Variable vfw_ap_1204, Parameter vmvm_1159
where
not func_0(vfw_resp_v8_1166, vi_1167, vnotif_ver_1171, vfw_ap_1204, vmvm_1159)
and func_2(func)
and func_3(vfw_resp_v8_1166, vi_1167, vnotif_ver_1171, vfw_ap_1204, vmvm_1159)
and vfw_resp_v8_1166.getType().hasName("iwl_tof_range_rsp_ntfy_v8 *")
and vi_1167.getType().hasName("int")
and vnotif_ver_1171.getType().hasName("u8")
and vfw_ap_1204.getType().hasName("iwl_tof_range_rsp_ap_entry_ntfy_v6 *")
and vmvm_1159.getType().hasName("iwl_mvm *")
and vfw_resp_v8_1166.getParentScope+() = func
and vi_1167.getParentScope+() = func
and vnotif_ver_1171.getParentScope+() = func
and vfw_ap_1204.getParentScope+() = func
and vmvm_1159.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
