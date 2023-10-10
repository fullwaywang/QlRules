/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_pcie_apm_init
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/iwl-pcie-apm-init
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_pcie_apm_init CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtrans_270) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="trans_cfg"
		and target_0.getQualifier().(VariableAccess).getTarget()=vtrans_270)
}

from Function func, Parameter vtrans_270
where
func_0(vtrans_270)
and vtrans_270.getType().hasName("iwl_trans *")
and vtrans_270.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
