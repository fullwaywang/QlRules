/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_pcie_apm_lp_xtal_enable
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/iwl-pcie-apm-lp-xtal-enable
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_pcie_apm_lp_xtal_enable CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtrans_368) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="trans_cfg"
		and target_0.getQualifier().(VariableAccess).getTarget()=vtrans_368)
}

from Function func, Parameter vtrans_368
where
func_0(vtrans_368)
and vtrans_368.getType().hasName("iwl_trans *")
and vtrans_368.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
