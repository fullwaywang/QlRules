/**
 * @name linux-f428fe4a04cc339166c8bbd489789760de3a0cee-rtnl_getlink
 * @id cpp/linux/f428fe4a04cc339166c8bbd489789760de3a0cee/rtnl-getlink
 * @description linux-f428fe4a04cc339166c8bbd489789760de3a0cee-rtnl_getlink NULL
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vskb_2866) {
	exists(ValueFieldAccess target_0 |
		target_0.getTarget().getName()="sk"
		and target_0.getQualifier().(PointerDereferenceExpr).getOperand().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cb"
		and target_0.getQualifier().(PointerDereferenceExpr).getOperand().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vskb_2866)
}

from Function func, Parameter vskb_2866
where
not func_0(vskb_2866)
and vskb_2866.getType().hasName("sk_buff *")
and vskb_2866.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
