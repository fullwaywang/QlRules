/**
 * @name linux-6b7339f4c31ad69c8e9c0b2859276e22cf72176d-do_anonymous_page
 * @id cpp/linux/6b7339f4c31ad69c8e9c0b2859276e22cf72176d/do-anonymous-page
 * @description linux-6b7339f4c31ad69c8e9c0b2859276e22cf72176d-do_anonymous_page 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vvma_2662, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="vm_flags"
		and target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvma_2662
		and target_0.getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="8"
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="2"
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_0))
}

from Function func, Parameter vvma_2662
where
not func_0(vvma_2662, func)
and vvma_2662.getType().hasName("vm_area_struct *")
and vvma_2662.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
