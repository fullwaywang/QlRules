/**
 * @name openssl-7fd4ce6a997be5f5c9e744ac527725c2850de203-tls_decrypt_ticket
 * @id cpp/openssl/7fd4ce6a997be5f5c9e744ac527725c2850de203/tls-decrypt-ticket
 * @description openssl-7fd4ce6a997be5f5c9e744ac527725c2850de203-tls_decrypt_ticket CVE-2014-3567
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vmlen_2303, Variable vtick_hmac_2304, Parameter vetick_2296, Parameter veticklen_2296) {
	exists(ReturnStmt target_1 |
		target_1.getExpr().(Literal).getValue()="2"
		and target_1.getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("CRYPTO_memcmp")
		and target_1.getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtick_hmac_2304
		and target_1.getParent().(IfStmt).getCondition().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vetick_2296
		and target_1.getParent().(IfStmt).getCondition().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=veticklen_2296
		and target_1.getParent().(IfStmt).getCondition().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vmlen_2303)
}

predicate func_2(Variable vctx_2306, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("EVP_CIPHER_CTX_cleanup")
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vctx_2306
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2)
}

from Function func, Variable vmlen_2303, Variable vtick_hmac_2304, Variable vctx_2306, Parameter vetick_2296, Parameter veticklen_2296
where
func_1(vmlen_2303, vtick_hmac_2304, vetick_2296, veticklen_2296)
and func_2(vctx_2306, func)
and vmlen_2303.getType().hasName("int")
and vtick_hmac_2304.getType().hasName("unsigned char[64]")
and vctx_2306.getType().hasName("EVP_CIPHER_CTX")
and vetick_2296.getType().hasName("const unsigned char *")
and veticklen_2296.getType().hasName("int")
and vmlen_2303.getParentScope+() = func
and vtick_hmac_2304.getParentScope+() = func
and vctx_2306.getParentScope+() = func
and vetick_2296.getParentScope+() = func
and veticklen_2296.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
