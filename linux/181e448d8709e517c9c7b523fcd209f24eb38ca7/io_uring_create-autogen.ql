/**
 * @name linux-181e448d8709e517c9c7b523fcd209f24eb38ca7-io_uring_create
 * @id cpp/linux/181e448d8709e517c9c7b523fcd209f24eb38ca7/io-uring-create
 * @description linux-181e448d8709e517c9c7b523fcd209f24eb38ca7-io_uring_create 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vctx_4666, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="creds"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_4666
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("prepare_creds")
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_0))
}

predicate func_1(Variable vctx_4666) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="user"
		and target_1.getQualifier().(VariableAccess).getTarget()=vctx_4666)
}

from Function func, Variable vctx_4666
where
not func_0(vctx_4666, func)
and vctx_4666.getType().hasName("io_ring_ctx *")
and func_1(vctx_4666)
and vctx_4666.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
