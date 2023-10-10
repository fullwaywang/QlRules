/**
 * @name linux-a3727a8bac0a9e77c70820655fd8715523ba3db7-selinux_msg_queue_msgrcv
 * @id cpp/linux/a3727a8bac0a9e77c70820655fd8715523ba3db7/selinux-msg-queue-msgrcv
 * @description linux-a3727a8bac0a9e77c70820655fd8715523ba3db7-selinux_msg_queue_msgrcv 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtarget_6219) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("task_sid_subj")
		and not target_0.getTarget().hasName("task_sid_obj")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vtarget_6219)
}

from Function func, Parameter vtarget_6219
where
func_0(vtarget_6219)
and vtarget_6219.getType().hasName("task_struct *")
and vtarget_6219.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
