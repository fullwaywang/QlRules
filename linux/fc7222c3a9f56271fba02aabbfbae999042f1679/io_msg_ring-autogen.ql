/**
 * @name linux-fc7222c3a9f56271fba02aabbfbae999042f1679-io_msg_ring
 * @id cpp/linux/fc7222c3a9f56271fba02aabbfbae999042f1679/io-msg-ring
 * @description linux-fc7222c3a9f56271fba02aabbfbae999042f1679-io_msg_ring 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vreq_142, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_0.getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreq_142
		and target_0.getThen() instanceof ExprStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vreq_142, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("io_put_file")
		and target_1.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="file"
		and target_1.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_1.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreq_142
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1)
}

predicate func_2(Variable vret_145, Parameter vreq_142) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("io_req_set_res")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vreq_142
		and target_2.getArgument(1).(VariableAccess).getTarget()=vret_145
		and target_2.getArgument(2).(Literal).getValue()="0")
}

from Function func, Variable vret_145, Parameter vreq_142
where
not func_0(vreq_142, func)
and func_1(vreq_142, func)
and vreq_142.getType().hasName("io_kiocb *")
and func_2(vret_145, vreq_142)
and vret_145.getParentScope+() = func
and vreq_142.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
