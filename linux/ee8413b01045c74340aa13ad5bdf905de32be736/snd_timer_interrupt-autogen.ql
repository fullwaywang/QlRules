/**
 * @name linux-ee8413b01045c74340aa13ad5bdf905de32be736-snd_timer_interrupt
 * @id cpp/linux/ee8413b01045c74340aa13ad5bdf905de32be736/snd_timer_interrupt
 * @description linux-ee8413b01045c74340aa13ad5bdf905de32be736-snd_timer_interrupt 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vti_658) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("list_del")
		and not target_0.getTarget().hasName("list_del_init")
		and target_0.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="active_list"
		and target_0.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vti_658)
}

from Function func, Variable vti_658
where
func_0(vti_658)
and vti_658.getType().hasName("snd_timer_instance *")
and vti_658.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
