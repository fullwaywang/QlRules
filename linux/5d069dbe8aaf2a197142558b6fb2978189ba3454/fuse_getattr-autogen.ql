/**
 * @name linux-5d069dbe8aaf2a197142558b6fb2978189ba3454-fuse_getattr
 * @id cpp/linux/5d069dbe8aaf2a197142558b6fb2978189ba3454/fuse-getattr
 * @description linux-5d069dbe8aaf2a197142558b6fb2978189ba3454-fuse_getattr fs/fuse/dir.c
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vinode_1800, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(FunctionCall).getTarget().hasName("fuse_is_bad")
		and target_0.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinode_1800
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-5"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="5"
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_0))
}

predicate func_1(Variable vinode_1800) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("get_fuse_conn")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vinode_1800)
}

from Function func, Variable vinode_1800
where
not func_0(vinode_1800, func)
and vinode_1800.getType().hasName("inode *")
and func_1(vinode_1800)
and vinode_1800.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
