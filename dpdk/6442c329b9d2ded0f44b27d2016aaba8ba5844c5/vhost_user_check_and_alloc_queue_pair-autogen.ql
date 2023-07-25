/**
 * @name dpdk-6442c329b9d2ded0f44b27d2016aaba8ba5844c5-vhost_user_check_and_alloc_queue_pair
 * @id cpp/dpdk/6442c329b9d2ded0f44b27d2016aaba8ba5844c5/vhost-user-check-and-alloc-queue-pair
 * @description dpdk-6442c329b9d2ded0f44b27d2016aaba8ba5844c5-lib/vhost/vhost_user.c-vhost_user_check_and_alloc_queue_pair CVE-2021-3839
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vvring_idx_2869, ValueFieldAccess target_3, ExprStmt target_4, RelationalOperation target_5) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vvring_idx_2869
		and target_1.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="num_queues"
		and target_1.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="inflight"
		and target_1.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="payload"
		and target_1.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="msg"
		and target_1.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_1.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_3
		and target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_5.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_2(ValueFieldAccess target_3, Function func) {
	exists(BreakStmt target_2 |
		target_2.toString() = "break;"
		and target_2.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_3
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(ValueFieldAccess target_3) {
		target_3.getTarget().getName()="master"
		and target_3.getQualifier().(ValueFieldAccess).getTarget().getName()="request"
		and target_3.getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="msg"
}

predicate func_4(Variable vvring_idx_2869, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vvring_idx_2869
		and target_4.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="index"
		and target_4.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="addr"
		and target_4.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="payload"
		and target_4.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="msg"
}

predicate func_5(Variable vvring_idx_2869, RelationalOperation target_5) {
		 (target_5 instanceof GEExpr or target_5 instanceof LEExpr)
		and target_5.getGreaterOperand().(VariableAccess).getTarget()=vvring_idx_2869
		and target_5.getLesserOperand().(Literal).getValue()="256"
}

from Function func, Variable vvring_idx_2869, ValueFieldAccess target_3, ExprStmt target_4, RelationalOperation target_5
where
not func_1(vvring_idx_2869, target_3, target_4, target_5)
and not func_2(target_3, func)
and func_3(target_3)
and func_4(vvring_idx_2869, target_4)
and func_5(vvring_idx_2869, target_5)
and vvring_idx_2869.getType().hasName("uint32_t")
and vvring_idx_2869.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
