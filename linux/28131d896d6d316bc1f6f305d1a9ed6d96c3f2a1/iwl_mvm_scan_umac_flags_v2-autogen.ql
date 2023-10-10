/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_mvm_scan_umac_flags_v2
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/iwl-mvm-scan-umac-flags-v2
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_mvm_scan_umac_flags_v2 CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vparams_1992, Variable vflags_1996) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="n_ssids"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparams_1992
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="ssid_len"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="ssids"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparams_1992
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_0.getThen().(ExprStmt).getExpr().(AssignOrExpr).getLValue().(VariableAccess).getTarget()=vflags_1996
		and target_0.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="n_ssids"
		and target_0.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparams_1992
		and target_0.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0")
}

predicate func_1(Parameter vparams_1992) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="n_ssids"
		and target_1.getQualifier().(VariableAccess).getTarget()=vparams_1992)
}

from Function func, Parameter vparams_1992, Variable vflags_1996
where
not func_0(vparams_1992, vflags_1996)
and vparams_1992.getType().hasName("iwl_mvm_scan_params *")
and func_1(vparams_1992)
and vflags_1996.getType().hasName("u16")
and vparams_1992.getParentScope+() = func
and vflags_1996.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
