/**
 * @name linux-fd4d9c7d0c71866ec0c2825189ebd2ce35bd95b8-kmem_cache_alloc_bulk
 * @id cpp/linux/fd4d9c7d0c71866ec0c2825189ebd2ce35bd95b8/kmem_cache_alloc_bulk
 * @description linux-fd4d9c7d0c71866ec0c2825189ebd2ce35bd95b8-kmem_cache_alloc_bulk 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_1(Variable vc_3158, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="tid"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_3158
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("next_tid")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tid"
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_3158
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1)
}

predicate func_2(Variable vc_3158) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="freelist"
		and target_2.getQualifier().(VariableAccess).getTarget()=vc_3158)
}

from Function func, Variable vc_3158
where
func_1(vc_3158, func)
and vc_3158.getType().hasName("kmem_cache_cpu *")
and func_2(vc_3158)
and vc_3158.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
