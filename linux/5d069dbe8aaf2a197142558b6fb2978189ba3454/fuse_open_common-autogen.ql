/**
 * @name linux-5d069dbe8aaf2a197142558b6fb2978189ba3454-fuse_open_common
 * @id cpp/linux/5d069dbe8aaf2a197142558b6fb2978189ba3454/fuse-open-common
 * @description linux-5d069dbe8aaf2a197142558b6fb2978189ba3454-fuse_open_common fs/fuse/dir.c
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vinode_224, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(FunctionCall).getTarget().hasName("fuse_is_bad")
		and target_0.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinode_224
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-5"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="5"
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vinode_224) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="i_flags"
		and target_1.getQualifier().(VariableAccess).getTarget()=vinode_224)
}

from Function func, Parameter vinode_224
where
not func_0(vinode_224, func)
and vinode_224.getType().hasName("inode *")
and func_1(vinode_224)
and vinode_224.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
