/**
 * @name linux-c9fbd7bbc23dbdd73364be4d045e5d3612cf6e82-xfs_fs_put_super
 * @id cpp/linux/c9fbd7bbc23dbdd73364be4d045e5d3612cf6e82/xfs_fs_put_super
 * @description linux-c9fbd7bbc23dbdd73364be4d045e5d3612cf6e82-xfs_fs_put_super 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vsb_1788, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="s_fs_info"
		and target_0.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsb_1788
		and target_0.getThen().(ReturnStmt).toString() = "return ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(1)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(1).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vsb_1788, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="s_fs_info"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsb_1788
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_1))
}

predicate func_2(Parameter vsb_1788) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="s_fs_info"
		and target_2.getQualifier().(VariableAccess).getTarget()=vsb_1788)
}

from Function func, Parameter vsb_1788
where
not func_0(vsb_1788, func)
and not func_1(vsb_1788, func)
and vsb_1788.getType().hasName("super_block *")
and func_2(vsb_1788)
and vsb_1788.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
