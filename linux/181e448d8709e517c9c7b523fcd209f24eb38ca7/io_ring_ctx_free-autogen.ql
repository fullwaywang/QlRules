/**
 * @name linux-181e448d8709e517c9c7b523fcd209f24eb38ca7-io_ring_ctx_free
 * @id cpp/linux/181e448d8709e517c9c7b523fcd209f24eb38ca7/io-ring-ctx-free
 * @description linux-181e448d8709e517c9c7b523fcd209f24eb38ca7-io_ring_ctx_free 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctx_4340, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("put_cred")
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="creds"
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_4340
		and (func.getEntryPoint().(BlockStmt).getStmt(12)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(12).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vctx_4340) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="user"
		and target_1.getQualifier().(VariableAccess).getTarget()=vctx_4340)
}

from Function func, Parameter vctx_4340
where
not func_0(vctx_4340, func)
and vctx_4340.getType().hasName("io_ring_ctx *")
and func_1(vctx_4340)
and vctx_4340.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
