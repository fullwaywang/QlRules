/**
 * @name linux-5d069dbe8aaf2a197142558b6fb2978189ba3454-fuse_permission
 * @id cpp/linux/5d069dbe8aaf2a197142558b6fb2978189ba3454/fuse-permission
 * @description linux-5d069dbe8aaf2a197142558b6fb2978189ba3454-fuse_permission fs/fuse/dir.c
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vinode_1234, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(FunctionCall).getTarget().hasName("fuse_is_bad")
		and target_0.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinode_1234
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-5"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="5"
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vinode_1234) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("get_fuse_conn")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vinode_1234)
}

from Function func, Parameter vinode_1234
where
not func_0(vinode_1234, func)
and vinode_1234.getType().hasName("inode *")
and func_1(vinode_1234)
and vinode_1234.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
