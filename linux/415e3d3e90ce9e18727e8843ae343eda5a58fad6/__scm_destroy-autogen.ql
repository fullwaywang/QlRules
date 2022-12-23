/**
 * @name linux-415e3d3e90ce9e18727e8843ae343eda5a58fad6-__scm_destroy
 * @id cpp/linux/415e3d3e90ce9e18727e8843ae343eda5a58fad6/__scm_destroy
 * @description linux-415e3d3e90ce9e18727e8843ae343eda5a58fad6-__scm_destroy 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vfpl_115) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("free_uid")
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="user"
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfpl_115
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vfpl_115)
}

predicate func_1(Variable vfpl_115) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="fp"
		and target_1.getQualifier().(VariableAccess).getTarget()=vfpl_115)
}

from Function func, Variable vfpl_115
where
not func_0(vfpl_115)
and vfpl_115.getType().hasName("scm_fp_list *")
and func_1(vfpl_115)
and vfpl_115.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
