/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_init_otp_access
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/iwl-init-otp-access
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_init_otp_access CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtrans_138) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="trans_cfg"
		and target_0.getQualifier().(VariableAccess).getTarget()=vtrans_138
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("iwl_finish_nic_init")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtrans_138)
}

from Function func, Parameter vtrans_138
where
func_0(vtrans_138)
and vtrans_138.getType().hasName("iwl_trans *")
and vtrans_138.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
