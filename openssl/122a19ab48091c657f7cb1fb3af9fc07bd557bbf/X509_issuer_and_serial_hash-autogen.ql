/**
 * @name openssl-122a19ab48091c657f7cb1fb3af9fc07bd557bbf-X509_issuer_and_serial_hash
 * @id cpp/openssl/122a19ab48091c657f7cb1fb3af9fc07bd557bbf/X509-issuer-and-serial-hash
 * @description openssl-122a19ab48091c657f7cb1fb3af9fc07bd557bbf-X509_issuer_and_serial_hash CVE-2021-23841
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vf_37, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vf_37
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(GotoStmt).toString() = "goto ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_0))
}

predicate func_1(Variable vf_37, Parameter va_32) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(VariableAccess).getTarget()=vf_37
		and target_1.getRValue().(FunctionCall).getTarget().hasName("X509_NAME_oneline")
		and target_1.getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="issuer"
		and target_1.getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cert_info"
		and target_1.getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_32
		and target_1.getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_1.getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0")
}

from Function func, Variable vf_37, Parameter va_32
where
not func_0(vf_37, func)
and vf_37.getType().hasName("char *")
and func_1(vf_37, va_32)
and va_32.getType().hasName("X509 *")
and vf_37.getParentScope+() = func
and va_32.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
