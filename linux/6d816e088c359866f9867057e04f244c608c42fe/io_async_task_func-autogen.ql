/**
 * @name linux-6d816e088c359866f9867057e04f244c608c42fe-io_async_task_func
 * @id cpp/linux/6d816e088c359866f9867057e04f244c608c42fe/io_async_task_func
 * @description linux-6d816e088c359866f9867057e04f244c608c42fe-io_async_task_func 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vreq_4747, Variable vapoll_4748, Variable vctx_4749) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("percpu_ref_put")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="refs"
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_4749
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("io_poll_rewait")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vreq_4747
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="poll"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vapoll_4748)
}

predicate func_2(Variable vctx_4749) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="(unknown field)"
		and target_2.getQualifier().(VariableAccess).getTarget()=vctx_4749)
}

from Function func, Variable vreq_4747, Variable vapoll_4748, Variable vctx_4749
where
not func_0(vreq_4747, vapoll_4748, vctx_4749)
and vreq_4747.getType().hasName("io_kiocb *")
and vapoll_4748.getType().hasName("async_poll *")
and vctx_4749.getType().hasName("io_ring_ctx *")
and func_2(vctx_4749)
and vreq_4747.getParentScope+() = func
and vapoll_4748.getParentScope+() = func
and vctx_4749.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
