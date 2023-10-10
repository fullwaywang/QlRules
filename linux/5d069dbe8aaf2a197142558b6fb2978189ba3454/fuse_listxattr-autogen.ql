/**
 * @name linux-5d069dbe8aaf2a197142558b6fb2978189ba3454-fuse_listxattr
 * @id cpp/linux/5d069dbe8aaf2a197142558b6fb2978189ba3454/fuse-listxattr
 * @description linux-5d069dbe8aaf2a197142558b6fb2978189ba3454-fuse_listxattr fs/fuse/dir.c
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vinode_109, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(FunctionCall).getTarget().hasName("fuse_is_bad")
		and target_0.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinode_109
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-5"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="5"
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_0))
}

predicate func_1(Variable vinode_109) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("get_fuse_mount")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vinode_109)
}

from Function func, Variable vinode_109
where
not func_0(vinode_109, func)
and vinode_109.getType().hasName("inode *")
and func_1(vinode_109)
and vinode_109.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
