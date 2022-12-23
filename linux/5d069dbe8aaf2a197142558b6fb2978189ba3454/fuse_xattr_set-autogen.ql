/**
 * @name linux-5d069dbe8aaf2a197142558b6fb2978189ba3454-fuse_xattr_set
 * @id cpp/linux/5d069dbe8aaf2a197142558b6fb2978189ba3454/fuse-xattr-set
 * @description linux-5d069dbe8aaf2a197142558b6fb2978189ba3454-fuse_xattr_set fs/fuse/dir.c
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vinode_185, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(FunctionCall).getTarget().hasName("fuse_is_bad")
		and target_0.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinode_185
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-5"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="5"
		and (func.getEntryPoint().(BlockStmt).getStmt(0)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(0).getFollowingStmt()=target_0))
}

from Function func, Parameter vinode_185
where
not func_0(vinode_185, func)
and vinode_185.getType().hasName("inode *")
and vinode_185.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
