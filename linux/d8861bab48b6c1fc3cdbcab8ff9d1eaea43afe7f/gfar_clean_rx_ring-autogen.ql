/**
 * @name linux-d8861bab48b6c1fc3cdbcab8ff9d1eaea43afe7f-gfar_clean_rx_ring
 * @id cpp/linux/d8861bab48b6c1fc3cdbcab8ff9d1eaea43afe7f/gfar_clean_rx_ring
 * @description linux-d8861bab48b6c1fc3cdbcab8ff9d1eaea43afe7f-gfar_clean_rx_ring 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vskb_2535, Parameter vrx_queue_2528, Variable vlstatus_2543) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vskb_2535
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vlstatus_2543
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="67108864"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1024"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="16"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("consume_skb")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vskb_2535
		and target_0.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_0.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(ValueFieldAccess).getTarget().getName()="rx_dropped"
		and target_0.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="stats"
		and target_0.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrx_queue_2528)
}

predicate func_4(Variable vskb_2535) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vskb_2535
		and target_4.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0")
}

predicate func_5(Parameter vrx_queue_2528) {
	exists(PointerFieldAccess target_5 |
		target_5.getTarget().getName()="rx_bd_base"
		and target_5.getQualifier().(VariableAccess).getTarget()=vrx_queue_2528)
}

predicate func_6(Variable vlstatus_2543) {
	exists(BitwiseAndExpr target_6 |
		target_6.getLeftOperand().(VariableAccess).getTarget()=vlstatus_2543
		and target_6.getRightOperand().(BinaryBitwiseOperation).getValue()="-2147483648"
		and target_6.getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="32768"
		and target_6.getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="16"
		and target_6.getParent().(IfStmt).getThen().(BreakStmt).toString() = "break;")
}

from Function func, Variable vskb_2535, Parameter vrx_queue_2528, Variable vlstatus_2543
where
not func_0(vskb_2535, vrx_queue_2528, vlstatus_2543)
and func_4(vskb_2535)
and vskb_2535.getType().hasName("sk_buff *")
and vrx_queue_2528.getType().hasName("gfar_priv_rx_q *")
and func_5(vrx_queue_2528)
and vlstatus_2543.getType().hasName("u32")
and func_6(vlstatus_2543)
and vskb_2535.getParentScope+() = func
and vrx_queue_2528.getParentScope+() = func
and vlstatus_2543.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
