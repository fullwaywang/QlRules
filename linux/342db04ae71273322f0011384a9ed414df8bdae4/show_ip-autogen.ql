/**
 * @name linux-342db04ae71273322f0011384a9ed414df8bdae4-show_ip
 * @id cpp/linux/342db04ae71273322f0011384a9ed414df8bdae4/show-ip
 * @description linux-342db04ae71273322f0011384a9ed414df8bdae4-show_ip 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Parameter vregs_109) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="ip"
		and target_1.getQualifier().(VariableAccess).getTarget()=vregs_109)
}

from Function func, Parameter vregs_109
where
func_1(vregs_109)
and vregs_109.getType().hasName("pt_regs *")
and vregs_109.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
