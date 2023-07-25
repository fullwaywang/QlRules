/**
 * @name openssl-349a41da1ad88ad87825414752a8ff5fdd6a6c3f-rsa_builtin_keygen
 * @id cpp/openssl/349a41da1ad88ad87825414752a8ff5fdd6a6c3f/rsa-builtin-keygen
 * @description openssl-349a41da1ad88ad87825414752a8ff5fdd6a6c3f-crypto/rsa/rsa_gen.c-rsa_builtin_keygen CVE-2018-0737
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vrsa_104, EqualityOperation target_2, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="flags"
		and target_0.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p"
		and target_0.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrsa_104
		and target_0.getExpr().(AssignOrExpr).getRValue().(Literal).getValue()="4"
		and (func.getEntryPoint().(BlockStmt).getStmt(26)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(26).getFollowingStmt()=target_0)
		and target_2.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vrsa_104, NotExpr target_3, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="flags"
		and target_1.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="q"
		and target_1.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrsa_104
		and target_1.getExpr().(AssignOrExpr).getRValue().(Literal).getValue()="4"
		and (func.getEntryPoint().(BlockStmt).getStmt(27)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(27).getFollowingStmt()=target_1)
		and target_1.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vrsa_104, EqualityOperation target_2) {
		target_2.getAnOperand().(FunctionCall).getTarget().hasName("BN_copy")
		and target_2.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="e"
		and target_2.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrsa_104
		and target_2.getAnOperand().(Literal).getValue()="0"
}

predicate func_3(Parameter vrsa_104, NotExpr target_3) {
		target_3.getOperand().(FunctionCall).getTarget().hasName("BN_generate_prime_ex")
		and target_3.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="p"
		and target_3.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrsa_104
		and target_3.getOperand().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_3.getOperand().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_3.getOperand().(FunctionCall).getArgument(4).(Literal).getValue()="0"
}

from Function func, Parameter vrsa_104, EqualityOperation target_2, NotExpr target_3
where
not func_0(vrsa_104, target_2, func)
and not func_1(vrsa_104, target_3, func)
and func_2(vrsa_104, target_2)
and func_3(vrsa_104, target_3)
and vrsa_104.getType().hasName("RSA *")
and vrsa_104.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
