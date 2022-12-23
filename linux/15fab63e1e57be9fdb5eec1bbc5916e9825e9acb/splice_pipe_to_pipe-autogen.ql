/**
 * @name linux-15fab63e1e57be9fdb5eec1bbc5916e9825e9acb-splice_pipe_to_pipe
 * @id cpp/linux/15fab63e1e57be9fdb5eec1bbc5916e9825e9acb/splice-pipe-to-pipe
 * @description linux-15fab63e1e57be9fdb5eec1bbc5916e9825e9acb-splice_pipe_to_pipe NULL
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vlen_1514, Variable vibuf_1516, Variable vret_1517, Parameter vipipe_1512) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("pipe_buf_get")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vipipe_1512
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vibuf_1516
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vret_1517
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_1517
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="14"
		and target_0.getThen().(BlockStmt).getStmt(1).(BreakStmt).toString() = "break;"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_1514
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="len"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vibuf_1516)
}

predicate func_6(Variable vibuf_1516, Parameter vipipe_1512) {
	exists(FunctionCall target_6 |
		target_6.getTarget().hasName("pipe_buf_get")
		and target_6.getArgument(0).(VariableAccess).getTarget()=vipipe_1512
		and target_6.getArgument(1).(VariableAccess).getTarget()=vibuf_1516)
}

predicate func_7(Variable vret_1517) {
	exists(AssignExpr target_7 |
		target_7.getLValue().(VariableAccess).getTarget()=vret_1517
		and target_7.getRValue().(UnaryMinusExpr).getValue()="-11"
		and target_7.getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="11")
}

from Function func, Parameter vlen_1514, Variable vibuf_1516, Variable vret_1517, Parameter vipipe_1512
where
not func_0(vlen_1514, vibuf_1516, vret_1517, vipipe_1512)
and func_6(vibuf_1516, vipipe_1512)
and vlen_1514.getType().hasName("size_t")
and vibuf_1516.getType().hasName("pipe_buffer *")
and vret_1517.getType().hasName("int")
and func_7(vret_1517)
and vipipe_1512.getType().hasName("pipe_inode_info *")
and vlen_1514.getParentScope+() = func
and vibuf_1516.getParentScope+() = func
and vret_1517.getParentScope+() = func
and vipipe_1512.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
