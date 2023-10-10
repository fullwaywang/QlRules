/**
 * @name linux-181e448d8709e517c9c7b523fcd209f24eb38ca7-io_sq_offload_start
 * @id cpp/linux/181e448d8709e517c9c7b523fcd209f24eb38ca7/io-sq-offload-start
 * @description linux-181e448d8709e517c9c7b523fcd209f24eb38ca7-io_sq_offload_start 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vdata_3965, Parameter vctx_3962, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="creds"
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_3965
		and target_0.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="creds"
		and target_0.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_3962
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vctx_3962) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="user"
		and target_1.getQualifier().(VariableAccess).getTarget()=vctx_3962)
}

from Function func, Variable vdata_3965, Parameter vctx_3962
where
not func_0(vdata_3965, vctx_3962, func)
and vdata_3965.getType().hasName("io_wq_data")
and vctx_3962.getType().hasName("io_ring_ctx *")
and func_1(vctx_3962)
and vdata_3965.getParentScope+() = func
and vctx_3962.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
