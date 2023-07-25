/**
 * @name tor-a282145b3634547ab84ccd959d0537c021ff7ffc-process_socks4_request
 * @id cpp/tor/a282145b3634547ab84ccd959d0537c021ff7ffc/process-socks4-request
 * @description tor-a282145b3634547ab84ccd959d0537c021ff7ffc-src/core/proto/proto_socks.c-process_socks4_request CVE-2023-23589
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vis_socks4a_233, BlockStmt target_2, IfStmt target_3) {
	exists(NotExpr target_0 |
		target_0.getOperand().(VariableAccess).getTarget()=vis_socks4a_233
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vis_socks4a_233
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("addressmap_have_mapping")
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="address"
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_2
		and target_0.getOperand().(VariableAccess).getLocation().isBefore(target_3.getCondition().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vis_socks4a_233, BlockStmt target_2, VariableAccess target_1) {
		target_1.getTarget()=vis_socks4a_233
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("addressmap_have_mapping")
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="address"
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_1.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_2
}

predicate func_2(BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("log_unsafe_socks_warning")
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="4"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="address"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="port"
}

predicate func_3(Parameter vis_socks4a_233, IfStmt target_3) {
		target_3.getCondition().(VariableAccess).getTarget()=vis_socks4a_233
		and target_3.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("log_fn_")
		and target_3.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="5"
		and target_3.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(BinaryBitwiseOperation).getValue()="256"
		and target_3.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Your application (using socks4a to port %d) instructed Tor to take care of the DNS resolution itself if necessary. This is good."
		and target_3.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="port"
}

from Function func, Parameter vis_socks4a_233, VariableAccess target_1, BlockStmt target_2, IfStmt target_3
where
not func_0(vis_socks4a_233, target_2, target_3)
and func_1(vis_socks4a_233, target_2, target_1)
and func_2(target_2)
and func_3(vis_socks4a_233, target_3)
and vis_socks4a_233.getType().hasName("int")
and vis_socks4a_233.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
