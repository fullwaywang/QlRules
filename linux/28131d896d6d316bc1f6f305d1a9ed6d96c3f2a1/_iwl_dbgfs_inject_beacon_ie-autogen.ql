/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-_iwl_dbgfs_inject_beacon_ie
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/-iwl-dbgfs-inject-beacon-ie
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-_iwl_dbgfs_inject_beacon_ie CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vmvm_1191, Variable vrate_1198) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("iwl_mvm_mac_ctxt_get_beacon_flags")
		and target_0.getArgument(0).(PointerFieldAccess).getTarget().getName()="fw"
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmvm_1191
		and target_0.getArgument(1).(VariableAccess).getTarget()=vrate_1198)
}

predicate func_2(Function func) {
	exists(DeclStmt target_2 |
		target_2.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof CTypedefType
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2)
}

predicate func_3(Variable vrate_1198, Variable vflags_1199) {
	exists(AssignExpr target_3 |
		target_3.getLValue().(VariableAccess).getTarget()=vflags_1199
		and target_3.getRValue().(FunctionCall).getTarget().hasName("iwl_mvm_mac80211_idx_to_hwrate")
		and target_3.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrate_1198)
}

predicate func_4(Variable vrate_1198, Variable vflags_1199, Function func) {
	exists(IfStmt target_4 |
		target_4.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vrate_1198
		and target_4.getThen().(ExprStmt).getExpr().(AssignOrExpr).getLValue().(VariableAccess).getTarget()=vflags_1199
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4)
}

predicate func_5(Variable vbeacon_cmd_1197, Variable vflags_1199, Function func) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="flags"
		and target_5.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vbeacon_cmd_1197
		and target_5.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vflags_1199
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_5)
}

predicate func_7(Parameter vmvm_1191) {
	exists(PointerFieldAccess target_7 |
		target_7.getTarget().getName()="beacon_inject_active"
		and target_7.getQualifier().(VariableAccess).getTarget()=vmvm_1191)
}

from Function func, Parameter vmvm_1191, Variable vbeacon_cmd_1197, Variable vrate_1198, Variable vflags_1199
where
not func_0(vmvm_1191, vrate_1198)
and func_2(func)
and func_3(vrate_1198, vflags_1199)
and func_4(vrate_1198, vflags_1199, func)
and func_5(vbeacon_cmd_1197, vflags_1199, func)
and vmvm_1191.getType().hasName("iwl_mvm *")
and func_7(vmvm_1191)
and vbeacon_cmd_1197.getType().hasName("iwl_mac_beacon_cmd")
and vrate_1198.getType().hasName("u8")
and vflags_1199.getType().hasName("u16")
and vmvm_1191.getParentScope+() = func
and vbeacon_cmd_1197.getParentScope+() = func
and vrate_1198.getParentScope+() = func
and vflags_1199.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
