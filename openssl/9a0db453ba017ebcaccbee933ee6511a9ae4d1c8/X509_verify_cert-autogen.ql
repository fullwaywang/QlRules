/**
 * @name openssl-9a0db453ba017ebcaccbee933ee6511a9ae4d1c8-X509_verify_cert
 * @id cpp/openssl/9a0db453ba017ebcaccbee933ee6511a9ae4d1c8/X509-verify-cert
 * @description openssl-9a0db453ba017ebcaccbee933ee6511a9ae4d1c8-crypto/x509/x509_vfy.c-X509_verify_cert CVE-2015-1793
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctx_152) {
	exists(AssignExpr target_0 |
		target_0.getLValue().(PointerFieldAccess).getTarget().getName()="last_untrusted"
		and target_0.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_152
		and target_0.getRValue().(FunctionCall).getTarget().hasName("sk_num")
		and target_0.getRValue().(FunctionCall).getArgument(0).(ConditionalExpr).getCondition().(Literal).getValue()="1"
		and target_0.getRValue().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(PointerFieldAccess).getTarget().getName()="chain"
		and target_0.getRValue().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_152
		and target_0.getRValue().(FunctionCall).getArgument(0).(ConditionalExpr).getElse().(Literal).getValue()="0")
}

predicate func_1(Parameter vctx_152, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="last_untrusted"
		and target_1.getQualifier().(VariableAccess).getTarget()=vctx_152
}

predicate func_2(Parameter vctx_152, NotExpr target_4, PostfixDecrExpr target_2) {
		target_2.getOperand().(PointerFieldAccess).getTarget().getName()="last_untrusted"
		and target_2.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_152
		and target_2.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getOperand().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_4(Parameter vctx_152, NotExpr target_4) {
		target_4.getOperand().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="check_issued"
		and target_4.getOperand().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_152
		and target_4.getOperand().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vctx_152
}

from Function func, Parameter vctx_152, PointerFieldAccess target_1, PostfixDecrExpr target_2, NotExpr target_4
where
not func_0(vctx_152)
and func_1(vctx_152, target_1)
and func_2(vctx_152, target_4, target_2)
and func_4(vctx_152, target_4)
and vctx_152.getType().hasName("X509_STORE_CTX *")
and vctx_152.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
