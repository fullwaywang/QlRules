/**
 * @name linux-eb66ae030829605d61fbef1909ce310e29f78821-move_ptes
 * @id cpp/linux/eb66ae030829605d61fbef1909ce310e29f78821/move_ptes
 * @description linux-eb66ae030829605d61fbef1909ce310e29f78821-move_ptes 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vpte_121) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("pte_present")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vpte_121)
}

predicate func_1(Variable vpte_121, Variable vforce_flush_123) {
	exists(LogicalAndExpr target_1 |
		target_1.getAnOperand() instanceof FunctionCall
		and target_1.getAnOperand().(FunctionCall).getTarget().hasName("pte_dirty")
		and target_1.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpte_121
		and target_1.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vforce_flush_123)
}

predicate func_2(Parameter vneed_flush_118, Variable vforce_flush_123) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vneed_flush_118
		and target_2.getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vforce_flush_123)
}

from Function func, Parameter vneed_flush_118, Variable vpte_121, Variable vforce_flush_123
where
func_0(vpte_121)
and func_1(vpte_121, vforce_flush_123)
and func_2(vneed_flush_118, vforce_flush_123)
and vneed_flush_118.getType().hasName("bool *")
and vpte_121.getType().hasName("pte_t")
and vforce_flush_123.getType().hasName("bool")
and vneed_flush_118.getParentScope+() = func
and vpte_121.getParentScope+() = func
and vforce_flush_123.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
