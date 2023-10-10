/**
 * @name linux-342db04ae71273322f0011384a9ed414df8bdae4-show_signal_msg
 * @id cpp/linux/342db04ae71273322f0011384a9ed414df8bdae4/show-signal-msg
 * @description linux-342db04ae71273322f0011384a9ed414df8bdae4-show_signal_msg 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Parameter vregs_821) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="ip"
		and target_1.getQualifier().(VariableAccess).getTarget()=vregs_821)
}

from Function func, Parameter vregs_821
where
func_1(vregs_821)
and vregs_821.getType().hasName("pt_regs *")
and vregs_821.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
