/**
 * @name linux-8c7188b23474cca017b3ef354c4a58456f68303a-rds_sendmsg
 * @id cpp/linux/8c7188b23474cca017b3ef354c4a58456f68303a/rds-sendmsg
 * @description linux-8c7188b23474cca017b3ef354c4a58456f68303a-rds_sendmsg CVE-2015-6937
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vsk_981, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("lock_sock")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsk_981
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_0))
}

predicate func_1(Variable vsk_981, Variable vrs_982, Variable vdaddr_984) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("release_sock")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsk_981
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vdaddr_984
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="rs_bound_addr"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrs_982
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0")
}

predicate func_3(Variable vsk_981) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("release_sock")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vsk_981)
}

from Function func, Variable vsk_981, Variable vrs_982, Variable vdaddr_984
where
not func_0(vsk_981, func)
and not func_1(vsk_981, vrs_982, vdaddr_984)
and vsk_981.getType().hasName("sock *")
and func_3(vsk_981)
and vrs_982.getType().hasName("rds_sock *")
and vdaddr_984.getType().hasName("__be32")
and vsk_981.getParentScope+() = func
and vrs_982.getParentScope+() = func
and vdaddr_984.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
