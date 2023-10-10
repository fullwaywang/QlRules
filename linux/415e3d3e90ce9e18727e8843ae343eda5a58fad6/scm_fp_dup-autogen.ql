/**
 * @name linux-415e3d3e90ce9e18727e8843ae343eda5a58fad6-scm_fp_dup
 * @id cpp/linux/415e3d3e90ce9e18727e8843ae343eda5a58fad6/scm_fp_dup
 * @description linux-415e3d3e90ce9e18727e8843ae343eda5a58fad6-scm_fp_dup 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vnew_fpl_327, Parameter vfpl_325) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="user"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnew_fpl_327
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("get_uid")
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="user"
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfpl_325
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vnew_fpl_327)
}

predicate func_1(Variable vnew_fpl_327) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="count"
		and target_1.getQualifier().(VariableAccess).getTarget()=vnew_fpl_327)
}

predicate func_2(Parameter vfpl_325) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="fp"
		and target_2.getQualifier().(VariableAccess).getTarget()=vfpl_325)
}

from Function func, Variable vnew_fpl_327, Parameter vfpl_325
where
not func_0(vnew_fpl_327, vfpl_325)
and vnew_fpl_327.getType().hasName("scm_fp_list *")
and func_1(vnew_fpl_327)
and vfpl_325.getType().hasName("scm_fp_list *")
and func_2(vfpl_325)
and vnew_fpl_327.getParentScope+() = func
and vfpl_325.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
