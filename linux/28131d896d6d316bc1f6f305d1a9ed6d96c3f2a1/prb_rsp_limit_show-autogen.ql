/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-prb_rsp_limit_show
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/prb-rsp-limit-show
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-prb_rsp_limit_show CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vbuf_209, Variable vretry_limit_214) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("snprintf")
		and not target_0.getTarget().hasName("sysfs_emit")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vbuf_209
		and target_0.getArgument(1).(Literal).getValue()="10"
		and target_0.getArgument(2).(StringLiteral).getValue()="%d\n"
		and target_0.getArgument(3).(VariableAccess).getTarget()=vretry_limit_214)
}

from Function func, Parameter vbuf_209, Variable vretry_limit_214
where
func_0(vbuf_209, vretry_limit_214)
and vbuf_209.getType().hasName("char *")
and vretry_limit_214.getType().hasName("u32")
and vbuf_209.getParentScope+() = func
and vretry_limit_214.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
