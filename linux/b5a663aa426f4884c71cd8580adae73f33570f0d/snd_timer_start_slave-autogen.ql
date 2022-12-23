/**
 * @name linux-b5a663aa426f4884c71cd8580adae73f33570f0d-snd_timer_start_slave
 * @id cpp/linux/b5a663aa426f4884c71cd8580adae73f33570f0d/snd_timer_start_slave
 * @description linux-b5a663aa426f4884c71cd8580adae73f33570f0d-snd_timer_start_slave 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_5(Parameter vtimeri_438) {
	exists(PointerFieldAccess target_5 |
		target_5.getTarget().getName()="flags"
		and target_5.getQualifier().(VariableAccess).getTarget()=vtimeri_438)
}

from Function func, Parameter vtimeri_438
where
vtimeri_438.getType().hasName("snd_timer_instance *")
and func_5(vtimeri_438)
and vtimeri_438.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
