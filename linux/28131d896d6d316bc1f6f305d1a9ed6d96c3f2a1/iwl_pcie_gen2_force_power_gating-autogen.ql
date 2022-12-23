/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_pcie_gen2_force_power_gating
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/iwl-pcie-gen2-force-power-gating
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_pcie_gen2_force_power_gating CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtrans_1733) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="trans_cfg"
		and target_0.getQualifier().(VariableAccess).getTarget()=vtrans_1733)
}

from Function func, Parameter vtrans_1733
where
func_0(vtrans_1733)
and vtrans_1733.getType().hasName("iwl_trans *")
and vtrans_1733.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
