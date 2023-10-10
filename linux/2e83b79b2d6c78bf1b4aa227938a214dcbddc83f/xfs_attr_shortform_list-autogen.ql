/**
 * @name linux-2e83b79b2d6c78bf1b4aa227938a214dcbddc83f-xfs_attr_shortform_list
 * @id cpp/linux/2e83b79b2d6c78bf1b4aa227938a214dcbddc83f/xfs_attr_shortform_list
 * @description linux-2e83b79b2d6c78bf1b4aa227938a214dcbddc83f-xfs_attr_shortform_list 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_1(Variable verror_77) {
	exists(ReturnStmt target_1 |
		target_1.getExpr().(VariableAccess).getTarget()=verror_77
		and target_1.getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=verror_77)
}

predicate func_2(Variable vsbuf_72, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("kmem_free")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuf_72
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2)
}

predicate func_3(Variable vsbuf_72) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("kmem_free")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vsbuf_72)
}

from Function func, Variable vsbuf_72, Variable verror_77
where
func_1(verror_77)
and func_2(vsbuf_72, func)
and vsbuf_72.getType().hasName("xfs_attr_sf_sort_t *")
and func_3(vsbuf_72)
and verror_77.getType().hasName("int")
and vsbuf_72.getParentScope+() = func
and verror_77.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
