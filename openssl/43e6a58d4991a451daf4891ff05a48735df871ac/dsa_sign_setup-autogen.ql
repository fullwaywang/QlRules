/**
 * @name openssl-43e6a58d4991a451daf4891ff05a48735df871ac-dsa_sign_setup
 * @id cpp/openssl/43e6a58d4991a451daf4891ff05a48735df871ac/dsa-sign-setup
 * @description openssl-43e6a58d4991a451daf4891ff05a48735df871ac-crypto/dsa/dsa_ossl.c-dsa_sign_setup CVE-2018-0734
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(AddExpr target_0 |
		target_0.getAnOperand() instanceof FunctionCall
		and target_0.getAnOperand().(MulExpr).getValue()="128"
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter vdsa_253, FunctionCall target_1) {
		target_1.getTarget().hasName("BN_num_bits")
		and target_1.getArgument(0).(PointerFieldAccess).getTarget().getName()="q"
		and target_1.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdsa_253
}

from Function func, Parameter vdsa_253, FunctionCall target_1
where
not func_0(func)
and func_1(vdsa_253, target_1)
and vdsa_253.getType().hasName("DSA *")
and vdsa_253.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
