/**
 * @name linux-246c320a8cfe0b11d81a4af38fa9985ef0cc9a4c-detach_vmas_to_be_unmapped
 * @id cpp/linux/246c320a8cfe0b11d81a4af38fa9985ef0cc9a4c/detach_vmas_to_be_unmapped
 * @description linux-246c320a8cfe0b11d81a4af38fa9985ef0cc9a4c-detach_vmas_to_be_unmapped 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vvma_2624, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vvma_2624
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="vm_flags"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvma_2624
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="256"
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vprev_2625, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vprev_2625
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="vm_flags"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vprev_2625
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_1))
}

predicate func_3(Parameter vvma_2624) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("vma_gap_update")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vvma_2624)
}

predicate func_4(Parameter vprev_2625) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("vm_end_gap")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vprev_2625)
}

from Function func, Parameter vvma_2624, Parameter vprev_2625
where
not func_0(vvma_2624, func)
and not func_1(vprev_2625, func)
and vvma_2624.getType().hasName("vm_area_struct *")
and func_3(vvma_2624)
and vprev_2625.getType().hasName("vm_area_struct *")
and func_4(vprev_2625)
and vvma_2624.getParentScope+() = func
and vprev_2625.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
