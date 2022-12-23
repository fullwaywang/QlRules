/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_pcie_apm_stop_master
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/iwl-pcie-apm-stop-master
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_pcie_apm_stop_master CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtrans_447) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("msleep")
		and target_0.getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="100"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="device_family"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="trans_cfg"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrans_447)
}

from Function func, Parameter vtrans_447
where
not func_0(vtrans_447)
and vtrans_447.getType().hasName("iwl_trans *")
and vtrans_447.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
