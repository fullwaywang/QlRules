/**
 * @name linux-15fab63e1e57be9fdb5eec1bbc5916e9825e9acb-link_pipe
 * @id cpp/linux/15fab63e1e57be9fdb5eec1bbc5916e9825e9acb/link-pipe
 * @description linux-15fab63e1e57be9fdb5eec1bbc5916e9825e9acb-link_pipe NULL
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vibuf_1631, Variable vret_1632, Parameter vipipe_1627) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("pipe_buf_get")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vipipe_1627
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vibuf_1631
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vret_1632
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_1632
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="14"
		and target_0.getThen().(BlockStmt).getStmt(1).(BreakStmt).toString() = "break;")
}

predicate func_6(Variable vibuf_1631, Parameter vipipe_1627) {
	exists(FunctionCall target_6 |
		target_6.getTarget().hasName("pipe_buf_get")
		and target_6.getArgument(0).(VariableAccess).getTarget()=vipipe_1627
		and target_6.getArgument(1).(VariableAccess).getTarget()=vibuf_1631)
}

predicate func_7(Variable vret_1632) {
	exists(AssignExpr target_7 |
		target_7.getLValue().(VariableAccess).getTarget()=vret_1632
		and target_7.getRValue().(UnaryMinusExpr).getValue()="-32"
		and target_7.getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="32")
}

from Function func, Variable vibuf_1631, Variable vret_1632, Parameter vipipe_1627
where
not func_0(vibuf_1631, vret_1632, vipipe_1627)
and func_6(vibuf_1631, vipipe_1627)
and vibuf_1631.getType().hasName("pipe_buffer *")
and vret_1632.getType().hasName("int")
and func_7(vret_1632)
and vipipe_1627.getType().hasName("pipe_inode_info *")
and vibuf_1631.getParentScope+() = func
and vret_1632.getParentScope+() = func
and vipipe_1627.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
