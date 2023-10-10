/**
 * @name linux-27ae357fa82be5ab73b2ef8d39dcb8ca2563483a-oom_reap_task
 * @id cpp/linux/27ae357fa82be5ab73b2ef8d39dcb8ca2563483a/oom_reap_task
 * @description linux-27ae357fa82be5ab73b2ef8d39dcb8ca2563483a-oom_reap_task CVE-2018-1000200
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vmm_587, Parameter vtsk_584) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("__oom_reap_task_mm")
		and not target_0.getTarget().hasName("oom_reap_task_mm")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vtsk_584
		and target_0.getArgument(1).(VariableAccess).getTarget()=vmm_587)
}

from Function func, Variable vmm_587, Parameter vtsk_584
where
func_0(vmm_587, vtsk_584)
and vmm_587.getType().hasName("mm_struct *")
and vtsk_584.getType().hasName("task_struct *")
and vmm_587.getParentScope+() = func
and vtsk_584.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
