/**
 * @name linux-3c52c6bb831f6335c176a0fc7214e26f43adbd11-do_ipv6_setsockopt
 * @id cpp/linux/3c52c6bb831f6335c176a0fc7214e26f43adbd11/do-ipv6-setsockopt
 * @description linux-3c52c6bb831f6335c176a0fc7214e26f43adbd11-do_ipv6_setsockopt 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vsk_394, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_0.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="skc_family"
		and target_0.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="__sk_common"
		and target_0.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsk_394
		and target_0.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="10"
		and target_0.getCondition().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_0.getThen().(GotoStmt).toString() = "goto ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_0))
}

predicate func_1(Function func) {
	exists(LabelStmt target_1 |
		target_1.toString() = "label ...:"
		and (func.getEntryPoint().(BlockStmt).getStmt(16)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(16).getFollowingStmt()=target_1))
}

predicate func_2(Parameter vsk_394) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("sockopt_lock_sock")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vsk_394)
}

from Function func, Parameter vsk_394
where
not func_0(vsk_394, func)
and not func_1(func)
and vsk_394.getType().hasName("sock *")
and func_2(vsk_394)
and vsk_394.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
