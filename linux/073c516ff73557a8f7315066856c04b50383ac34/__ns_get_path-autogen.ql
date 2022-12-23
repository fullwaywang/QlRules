/**
 * @name linux-073c516ff73557a8f7315066856c04b50383ac34-__ns_get_path
 * @id cpp/linux/073c516ff73557a8f7315066856c04b50383ac34/--ns-get-path
 * @description linux-073c516ff73557a8f7315066856c04b50383ac34-__ns_get_path 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vdentry_57, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="d_flags"
		and target_0.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdentry_57
		and target_0.getExpr().(AssignOrExpr).getRValue().(Literal).getValue()="128"
		and (func.getEntryPoint().(BlockStmt).getStmt(29)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(29).getFollowingStmt()=target_0))
}

predicate func_1(Variable vdentry_57, Variable vinode_58) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("d_instantiate")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vdentry_57
		and target_1.getArgument(1).(VariableAccess).getTarget()=vinode_58)
}

from Function func, Variable vdentry_57, Variable vinode_58
where
not func_0(vdentry_57, func)
and vdentry_57.getType().hasName("dentry *")
and func_1(vdentry_57, vinode_58)
and vinode_58.getType().hasName("inode *")
and vdentry_57.getParentScope+() = func
and vinode_58.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
