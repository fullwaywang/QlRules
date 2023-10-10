/**
 * @name linux-eb66ae030829605d61fbef1909ce310e29f78821-move_huge_pmd
 * @id cpp/linux/eb66ae030829605d61fbef1909ce310e29f78821/move_huge_pmd
 * @description linux-eb66ae030829605d61fbef1909ce310e29f78821-move_huge_pmd 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vpmd_1786) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("pmd_present")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vpmd_1786)
}

predicate func_1(Variable vpmd_1786, Variable vforce_flush_1788) {
	exists(LogicalAndExpr target_1 |
		target_1.getAnOperand() instanceof FunctionCall
		and target_1.getAnOperand().(FunctionCall).getTarget().hasName("pmd_dirty")
		and target_1.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpmd_1786
		and target_1.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vforce_flush_1788)
}

predicate func_2(Parameter vneed_flush_1783, Variable vforce_flush_1788) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vneed_flush_1783
		and target_2.getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vforce_flush_1788)
}

from Function func, Parameter vneed_flush_1783, Variable vpmd_1786, Variable vforce_flush_1788
where
func_0(vpmd_1786)
and func_1(vpmd_1786, vforce_flush_1788)
and func_2(vneed_flush_1783, vforce_flush_1788)
and vneed_flush_1783.getType().hasName("bool *")
and vpmd_1786.getType().hasName("pmd_t")
and vforce_flush_1788.getType().hasName("bool")
and vneed_flush_1783.getParentScope+() = func
and vpmd_1786.getParentScope+() = func
and vforce_flush_1788.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
