/**
 * @name linux-c9fbd7bbc23dbdd73364be4d045e5d3612cf6e82-xfs_fs_fill_super
 * @id cpp/linux/c9fbd7bbc23dbdd73364be4d045e5d3612cf6e82/xfs_fs_fill_super
 * @description linux-c9fbd7bbc23dbdd73364be4d045e5d3612cf6e82-xfs_fs_fill_super 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vsb_1608, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="s_fs_info"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsb_1608
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(64)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(64).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vsb_1608) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="s_root"
		and target_1.getQualifier().(VariableAccess).getTarget()=vsb_1608)
}

from Function func, Parameter vsb_1608
where
not func_0(vsb_1608, func)
and vsb_1608.getType().hasName("super_block *")
and func_1(vsb_1608)
and vsb_1608.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
