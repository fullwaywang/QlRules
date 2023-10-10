/**
 * @name linux-af368027a49a751d6ff4ee9e3f9961f35bb4fede-snd_timer_user_open
 * @id cpp/linux/af368027a49a751d6ff4ee9e3f9961f35bb4fede/snd_timer_user_open
 * @description linux-af368027a49a751d6ff4ee9e3f9961f35bb4fede-snd_timer_user_open 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vtu_1244) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="tread_sem"
		and target_0.getQualifier().(VariableAccess).getTarget()=vtu_1244)
}

predicate func_1(Function func) {
	exists(StringLiteral target_1 |
		target_1.getValue()="&tu->tread_sem"
		and not target_1.getValue()="&tu->ioctl_lock"
		and target_1.getEnclosingFunction() = func)
}

from Function func, Variable vtu_1244
where
func_0(vtu_1244)
and func_1(func)
and vtu_1244.getType().hasName("snd_timer_user *")
and vtu_1244.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
