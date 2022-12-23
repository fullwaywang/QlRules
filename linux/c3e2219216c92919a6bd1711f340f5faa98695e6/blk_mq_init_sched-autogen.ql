/**
 * @name linux-c3e2219216c92919a6bd1711f340f5faa98695e6-blk_mq_init_sched
 * @id cpp/linux/c3e2219216c92919a6bd1711f340f5faa98695e6/blk-mq-init-sched
 * @description linux-c3e2219216c92919a6bd1711f340f5faa98695e6-blk_mq_init_sched 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vq_488, Variable vret_493) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("blk_mq_sched_free_requests")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vq_488
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vret_493)
}

predicate func_2(Parameter vq_488) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="elevator"
		and target_2.getQualifier().(VariableAccess).getTarget()=vq_488)
}

predicate func_3(Parameter vq_488, Variable vhctx_490) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("blk_mq_debugfs_register_sched_hctx")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vq_488
		and target_3.getArgument(1).(VariableAccess).getTarget()=vhctx_490)
}

from Function func, Parameter vq_488, Variable vhctx_490, Variable vret_493
where
not func_0(vq_488, vret_493)
and vq_488.getType().hasName("request_queue *")
and func_2(vq_488)
and func_3(vq_488, vhctx_490)
and vhctx_490.getType().hasName("blk_mq_hw_ctx *")
and vret_493.getType().hasName("int")
and vq_488.getParentScope+() = func
and vhctx_490.getParentScope+() = func
and vret_493.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
