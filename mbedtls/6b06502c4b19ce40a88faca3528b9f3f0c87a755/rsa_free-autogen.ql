/**
 * @name mbedtls-6b06502c4b19ce40a88faca3528b9f3f0c87a755-rsa_free
 * @id cpp/mbedtls/6b06502c4b19ce40a88faca3528b9f3f0c87a755/rsa-free
 * @description mbedtls-6b06502c4b19ce40a88faca3528b9f3f0c87a755-library/rsa.c-rsa_free CVE-2013-5915
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctx_1355, Function func, ExprStmt target_0) {
		target_0.getExpr().(FunctionCall).getTarget().hasName("mpi_free")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="Vi"
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_1355
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0
}

predicate func_1(Parameter vctx_1355, Function func, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("mpi_free")
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="Vf"
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_1355
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1
}

from Function func, Parameter vctx_1355, ExprStmt target_0, ExprStmt target_1
where
func_0(vctx_1355, func, target_0)
and func_1(vctx_1355, func, target_1)
and vctx_1355.getType().hasName("rsa_context *")
and vctx_1355.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
