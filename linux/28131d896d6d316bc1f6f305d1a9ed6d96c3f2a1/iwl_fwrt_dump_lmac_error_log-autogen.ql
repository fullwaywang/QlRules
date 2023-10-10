/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_fwrt_dump_lmac_error_log
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/iwl-fwrt-dump-lmac-error-log
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_fwrt_dump_lmac_error_log CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_39(Variable vtrans_186) {
	exists(PointerFieldAccess target_39 |
		target_39.getTarget().getName()="trans_cfg"
		and target_39.getQualifier().(VariableAccess).getTarget()=vtrans_186)
}

from Function func, Variable vtrans_186
where
func_39(vtrans_186)
and vtrans_186.getType().hasName("iwl_trans *")
and vtrans_186.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
