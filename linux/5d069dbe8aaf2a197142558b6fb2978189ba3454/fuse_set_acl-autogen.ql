/**
 * @name linux-5d069dbe8aaf2a197142558b6fb2978189ba3454-fuse_set_acl
 * @id cpp/linux/5d069dbe8aaf2a197142558b6fb2978189ba3454/fuse-set-acl
 * @description linux-5d069dbe8aaf2a197142558b6fb2978189ba3454-fuse_set_acl fs/fuse/dir.c
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vinode_50, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(FunctionCall).getTarget().hasName("fuse_is_bad")
		and target_0.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinode_50
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-5"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="5"
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vinode_50) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("get_fuse_conn")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vinode_50)
}

from Function func, Parameter vinode_50
where
not func_0(vinode_50, func)
and vinode_50.getType().hasName("inode *")
and func_1(vinode_50)
and vinode_50.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
