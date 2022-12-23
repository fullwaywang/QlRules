/**
 * @name linux-1acb8f2a7a9f10543868ddd737e37424d5c36cf4-ql_alloc_large_buffers
 * @id cpp/linux/1acb8f2a7a9f10543868ddd737e37424d5c36cf4/ql_alloc_large_buffers
 * @description linux-1acb8f2a7a9f10543868ddd737e37424d5c36cf4-ql_alloc_large_buffers 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vskb_2754, Variable verr_2756) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("dev_kfree_skb_irq")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vskb_2754
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=verr_2756)
}

predicate func_1(Variable vskb_2754) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="data"
		and target_1.getQualifier().(VariableAccess).getTarget()=vskb_2754)
}

from Function func, Variable vskb_2754, Variable verr_2756
where
not func_0(vskb_2754, verr_2756)
and vskb_2754.getType().hasName("sk_buff *")
and func_1(vskb_2754)
and verr_2756.getType().hasName("int")
and vskb_2754.getParentScope+() = func
and verr_2756.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
