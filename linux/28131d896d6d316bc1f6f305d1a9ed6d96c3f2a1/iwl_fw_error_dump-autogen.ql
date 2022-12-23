/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_fw_error_dump
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/iwl-fw-error-dump
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_fw_error_dump CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vfwrt_2347) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="sanitize_ops"
		and target_0.getQualifier().(VariableAccess).getTarget()=vfwrt_2347)
}

predicate func_1(Parameter vfwrt_2347) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="sanitize_ctx"
		and target_1.getQualifier().(VariableAccess).getTarget()=vfwrt_2347)
}

predicate func_2(Parameter vfwrt_2347) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="trans"
		and target_2.getQualifier().(VariableAccess).getTarget()=vfwrt_2347)
}

from Function func, Parameter vfwrt_2347
where
not func_0(vfwrt_2347)
and not func_1(vfwrt_2347)
and vfwrt_2347.getType().hasName("iwl_fw_runtime *")
and func_2(vfwrt_2347)
and vfwrt_2347.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
