/**
 * @name linux-6b7339f4c31ad69c8e9c0b2859276e22cf72176d-do_fault
 * @id cpp/linux/6b7339f4c31ad69c8e9c0b2859276e22cf72176d/do-fault
 * @description linux-6b7339f4c31ad69c8e9c0b2859276e22cf72176d-do_fault 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vvma_3094, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="fault"
		and target_0.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="vm_ops"
		and target_0.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvma_3094
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="2"
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vvma_3094) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="vm_pgoff"
		and target_1.getQualifier().(VariableAccess).getTarget()=vvma_3094)
}

from Function func, Parameter vvma_3094
where
not func_0(vvma_3094, func)
and vvma_3094.getType().hasName("vm_area_struct *")
and func_1(vvma_3094)
and vvma_3094.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
