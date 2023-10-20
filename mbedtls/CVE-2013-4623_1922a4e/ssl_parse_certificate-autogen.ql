/**
 * @name mbedtls-1922a4e6aade7b1d685af19d4d9339ddb5c02859-ssl_parse_certificate
 * @id cpp/mbedtls/1922a4e6aade7b1d685af19d4d9339ddb5c02859/ssl-parse-certificate
 * @description mbedtls-1922a4e6aade7b1d685af19d4d9339ddb5c02859-library/ssl_tls.c-ssl_parse_certificate CVE-2013-4623
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vssl_2262, Variable vi_2265, Variable vn_2265, FunctionCall target_0) {
		target_0.getTarget().hasName("x509parse_crt")
		and not target_0.getTarget().hasName("x509parse_crt_der")
		and target_0.getArgument(0).(PointerFieldAccess).getTarget().getName()="peer_cert"
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="session_negotiate"
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vssl_2262
		and target_0.getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="in_msg"
		and target_0.getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vssl_2262
		and target_0.getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vi_2265
		and target_0.getArgument(2).(VariableAccess).getTarget()=vn_2265
}

from Function func, Parameter vssl_2262, Variable vi_2265, Variable vn_2265, FunctionCall target_0
where
func_0(vssl_2262, vi_2265, vn_2265, target_0)
and vssl_2262.getType().hasName("ssl_context *")
and vi_2265.getType().hasName("size_t")
and vn_2265.getType().hasName("size_t")
and vssl_2262.getParentScope+() = func
and vi_2265.getParentScope+() = func
and vn_2265.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
