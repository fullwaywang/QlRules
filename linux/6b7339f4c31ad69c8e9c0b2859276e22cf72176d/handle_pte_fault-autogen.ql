/**
 * @name linux-6b7339f4c31ad69c8e9c0b2859276e22cf72176d-handle_pte_fault
 * @id cpp/linux/6b7339f4c31ad69c8e9c0b2859276e22cf72176d/handle-pte-fault
 * @description linux-6b7339f4c31ad69c8e9c0b2859276e22cf72176d-handle_pte_fault 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vmm_3228, Parameter vvma_3229, Parameter vaddress_3229, Parameter vpte_3230, Parameter vpmd_3230, Parameter vflags_3230, Variable ventry_3232) {
	exists(IfStmt target_0 |
		target_0.getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_0.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="fault"
		and target_0.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="vm_ops"
		and target_0.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvma_3229
		and target_0.getCondition().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_0.getThen().(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("do_fault")
		and target_0.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmm_3228
		and target_0.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvma_3229
		and target_0.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vaddress_3229
		and target_0.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vpte_3230
		and target_0.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vpmd_3230
		and target_0.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vflags_3230
		and target_0.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=ventry_3232
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="vm_ops"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvma_3229)
}

from Function func, Parameter vmm_3228, Parameter vvma_3229, Parameter vaddress_3229, Parameter vpte_3230, Parameter vpmd_3230, Parameter vflags_3230, Variable ventry_3232
where
func_0(vmm_3228, vvma_3229, vaddress_3229, vpte_3230, vpmd_3230, vflags_3230, ventry_3232)
and vmm_3228.getType().hasName("mm_struct *")
and vvma_3229.getType().hasName("vm_area_struct *")
and vaddress_3229.getType().hasName("unsigned long")
and vpte_3230.getType().hasName("pte_t *")
and vpmd_3230.getType().hasName("pmd_t *")
and vflags_3230.getType().hasName("unsigned int")
and ventry_3232.getType().hasName("pte_t")
and vmm_3228.getParentScope+() = func
and vvma_3229.getParentScope+() = func
and vaddress_3229.getParentScope+() = func
and vpte_3230.getParentScope+() = func
and vpmd_3230.getParentScope+() = func
and vflags_3230.getParentScope+() = func
and ventry_3232.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
