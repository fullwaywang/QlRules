/**
 * @name linux-fac8e0f579695a3ecbc4d3cac369139d7f819971-dev_gro_receive
 * @id cpp/linux/fac8e0f579695a3ecbc4d3cac369139d7f819971/dev_gro_receive
 * @description linux-fac8e0f579695a3ecbc4d3cac369139d7f819971-dev_gro_receive 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vskb_4413) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="udp_mark"
		and target_0.getQualifier().(PointerFieldAccess).getTarget().getName()="cb"
		and target_0.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vskb_4413)
}

from Function func, Parameter vskb_4413
where
func_0(vskb_4413)
and vskb_4413.getType().hasName("sk_buff *")
and vskb_4413.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
