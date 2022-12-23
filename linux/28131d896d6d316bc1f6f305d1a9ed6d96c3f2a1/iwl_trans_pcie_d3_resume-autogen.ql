/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_trans_pcie_d3_resume
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/iwl-trans-pcie-d3-resume
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_trans_pcie_d3_resume CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_2(Parameter vtrans_1487) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="trans_cfg"
		and target_2.getQualifier().(VariableAccess).getTarget()=vtrans_1487
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("iwl_finish_nic_init")
		and target_2.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtrans_1487)
}

from Function func, Parameter vtrans_1487
where
func_2(vtrans_1487)
and vtrans_1487.getType().hasName("iwl_trans *")
and vtrans_1487.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
