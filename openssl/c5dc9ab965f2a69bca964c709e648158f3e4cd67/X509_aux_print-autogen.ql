/**
 * @name openssl-c5dc9ab965f2a69bca964c709e648158f3e4cd67-X509_aux_print
 * @id cpp/openssl/c5dc9ab965f2a69bca964c709e648158f3e4cd67/X509-aux-print
 * @description openssl-c5dc9ab965f2a69bca964c709e648158f3e4cd67-crypto/x509/t_x509.c-X509_aux_print CVE-2021-3712
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, StringLiteral target_0) {
		target_0.getValue()="%*sAlias: %s\n"
		and not target_0.getValue()="%*sAlias: %.*s\n"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Variable vi_348, FunctionCall target_4) {
	exists(AddressOfExpr target_1 |
		target_1.getOperand().(VariableAccess).getTarget()=vi_348
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("X509_alias_get0")
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1) instanceof Literal
		and target_4.getArgument(1).(VariableAccess).getLocation().isBefore(target_1.getOperand().(VariableAccess).getLocation()))
}

predicate func_4(Variable vi_348, FunctionCall target_4) {
		target_4.getTarget().hasName("OPENSSL_sk_value")
		and target_4.getArgument(0).(FunctionCall).getTarget().hasName("ossl_check_const_ASN1_OBJECT_sk_type")
		and target_4.getArgument(1).(VariableAccess).getTarget()=vi_348
}

from Function func, Variable vi_348, StringLiteral target_0, FunctionCall target_4
where
func_0(func, target_0)
and not func_1(vi_348, target_4)
and func_4(vi_348, target_4)
and vi_348.getType().hasName("int")
and vi_348.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
