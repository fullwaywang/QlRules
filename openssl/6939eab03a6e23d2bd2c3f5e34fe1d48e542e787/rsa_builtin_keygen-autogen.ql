/**
 * @name openssl-6939eab03a6e23d2bd2c3f5e34fe1d48e542e787-rsa_builtin_keygen
 * @id cpp/openssl/6939eab03a6e23d2bd2c3f5e34fe1d48e542e787/rsa-builtin-keygen
 * @description openssl-6939eab03a6e23d2bd2c3f5e34fe1d48e542e787-crypto/rsa/rsa_gen.c-rsa_builtin_keygen CVE-2018-0737
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vrsa_39, EqualityOperation target_2, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("BN_set_flags")
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="p"
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrsa_39
		and target_0.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="4"
		and (func.getEntryPoint().(BlockStmt).getStmt(24)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(24).getFollowingStmt()=target_0)
		and target_2.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vrsa_39, NotExpr target_3, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("BN_set_flags")
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="q"
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrsa_39
		and target_1.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="4"
		and (func.getEntryPoint().(BlockStmt).getStmt(25)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(25).getFollowingStmt()=target_1)
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vrsa_39, EqualityOperation target_2) {
		target_2.getAnOperand().(FunctionCall).getTarget().hasName("BN_copy")
		and target_2.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="e"
		and target_2.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrsa_39
		and target_2.getAnOperand().(Literal).getValue()="0"
}

predicate func_3(Parameter vrsa_39, NotExpr target_3) {
		target_3.getOperand().(FunctionCall).getTarget().hasName("BN_generate_prime_ex")
		and target_3.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="p"
		and target_3.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrsa_39
		and target_3.getOperand().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_3.getOperand().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_3.getOperand().(FunctionCall).getArgument(4).(Literal).getValue()="0"
}

from Function func, Parameter vrsa_39, EqualityOperation target_2, NotExpr target_3
where
not func_0(vrsa_39, target_2, func)
and not func_1(vrsa_39, target_3, func)
and func_2(vrsa_39, target_2)
and func_3(vrsa_39, target_3)
and vrsa_39.getType().hasName("RSA *")
and vrsa_39.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
