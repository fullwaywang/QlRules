/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-rs_pretty_rate
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/rs-pretty-rate
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-rs_pretty_rate CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vrate_520) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("rs_pretty_ant")
		and not target_0.getTarget().hasName("iwl_rs_pretty_ant")
		and target_0.getArgument(0).(PointerFieldAccess).getTarget().getName()="ant"
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrate_520)
}

from Function func, Parameter vrate_520
where
func_0(vrate_520)
and vrate_520.getType().hasName("const rs_rate *")
and vrate_520.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
