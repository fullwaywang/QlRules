/**
 * @name openssl-1b0fe00e2704b5e20334a16d3c9099d1ba2ef1be-test_rand_drbg_reseed
 * @id cpp/openssl/1b0fe00e2704b5e20334a16d3c9099d1ba2ef1be/test-rand-drbg-reseed
 * @description openssl-1b0fe00e2704b5e20334a16d3c9099d1ba2ef1be-test_rand_drbg_reseed CVE-2019-1549
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vpublic_679, Variable vprivate_679, Variable vmaster_679, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("test_true")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0) instanceof StringLiteral
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1) instanceof Literal
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(StringLiteral).getValue()="test_drbg_reseed_after_fork(master, public, private)"
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("test_drbg_reseed_after_fork")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmaster_679
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpublic_679
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vprivate_679
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(EqualityOperation).getAnOperand() instanceof Literal
		and target_0.getThen().(GotoStmt).toString() = "goto ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(28)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(28).getFollowingStmt()=target_0))
}

predicate func_1(Variable vpublic_679, Variable vprivate_679, Variable vmaster_679) {
	exists(EqualityOperation target_1 |
		target_1.getAnOperand().(FunctionCall).getTarget().hasName("test_drbg_reseed")
		and target_1.getAnOperand().(FunctionCall).getArgument(0) instanceof Literal
		and target_1.getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmaster_679
		and target_1.getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vpublic_679
		and target_1.getAnOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vprivate_679
		and target_1.getAnOperand().(FunctionCall).getArgument(4) instanceof Literal
		and target_1.getAnOperand().(FunctionCall).getArgument(5) instanceof Literal
		and target_1.getAnOperand().(FunctionCall).getArgument(6) instanceof Literal
		and target_1.getAnOperand().(FunctionCall).getArgument(7) instanceof Literal
		and target_1.getAnOperand() instanceof Literal
		and target_1.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("test_true")
		and target_1.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(0) instanceof StringLiteral
		and target_1.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(1) instanceof Literal
		and target_1.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(2).(StringLiteral).getValue()="test_drbg_reseed(1, master, public, private, 0, 0, 1, 0)")
}

from Function func, Variable vpublic_679, Variable vprivate_679, Variable vmaster_679
where
not func_0(vpublic_679, vprivate_679, vmaster_679, func)
and vpublic_679.getType().hasName("RAND_DRBG *")
and func_1(vpublic_679, vprivate_679, vmaster_679)
and vprivate_679.getType().hasName("RAND_DRBG *")
and vmaster_679.getType().hasName("RAND_DRBG *")
and vpublic_679.getParentScope+() = func
and vprivate_679.getParentScope+() = func
and vmaster_679.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
