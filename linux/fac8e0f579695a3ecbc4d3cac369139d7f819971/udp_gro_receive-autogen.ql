/**
 * @name linux-fac8e0f579695a3ecbc4d3cac369139d7f819971-udp_gro_receive
 * @id cpp/linux/fac8e0f579695a3ecbc4d3cac369139d7f819971/udp_gro_receive
 * @description linux-fac8e0f579695a3ecbc4d3cac369139d7f819971-udp_gro_receive 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vskb_305) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="udp_mark"
		and target_0.getQualifier().(PointerFieldAccess).getTarget().getName()="cb"
		and target_0.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vskb_305)
}

predicate func_1(Parameter vskb_305) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="udp_mark"
		and target_1.getQualifier().(PointerFieldAccess).getTarget().getName()="cb"
		and target_1.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vskb_305)
}

from Function func, Parameter vskb_305
where
func_0(vskb_305)
and func_1(vskb_305)
and vskb_305.getType().hasName("sk_buff *")
and vskb_305.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
