/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_pcie_gen2_apm_init
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/iwl-pcie-gen2-apm-init
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_pcie_gen2_apm_init CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtrans_20) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="trans_cfg"
		and target_0.getQualifier().(VariableAccess).getTarget()=vtrans_20)
}

from Function func, Parameter vtrans_20
where
func_0(vtrans_20)
and vtrans_20.getType().hasName("iwl_trans *")
and vtrans_20.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
