/**
 * @name linux-6d816e088c359866f9867057e04f244c608c42fe-io_rw_resubmit
 * @id cpp/linux/6d816e088c359866f9867057e04f244c608c42fe/io_rw_resubmit
 * @description linux-6d816e088c359866f9867057e04f244c608c42fe-io_rw_resubmit 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vctx_2312, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("percpu_ref_put")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="refs"
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_2312
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_0))
}

predicate func_1(Variable vreq_2311, Variable vctx_2312) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("io_sq_thread_acquire_mm")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vctx_2312
		and target_1.getArgument(1).(VariableAccess).getTarget()=vreq_2311)
}

from Function func, Variable vreq_2311, Variable vctx_2312
where
not func_0(vctx_2312, func)
and vctx_2312.getType().hasName("io_ring_ctx *")
and func_1(vreq_2311, vctx_2312)
and vreq_2311.getParentScope+() = func
and vctx_2312.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
