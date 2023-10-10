/**
 * @name linux-5d069dbe8aaf2a197142558b6fb2978189ba3454-fuse_get_acl
 * @id cpp/linux/5d069dbe8aaf2a197142558b6fb2978189ba3454/fuse-get-acl
 * @description linux-5d069dbe8aaf2a197142558b6fb2978189ba3454-fuse_get_acl fs/fuse/dir.c
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vinode_14, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(FunctionCall).getTarget().hasName("fuse_is_bad")
		and target_0.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinode_14
		and target_0.getThen().(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_PTR")
		and target_0.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(UnaryMinusExpr).getValue()="-5"
		and target_0.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(UnaryMinusExpr).getOperand().(Literal).getValue()="5"
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vinode_14) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("get_fuse_conn")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vinode_14)
}

from Function func, Parameter vinode_14
where
not func_0(vinode_14, func)
and vinode_14.getType().hasName("inode *")
and func_1(vinode_14)
and vinode_14.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
