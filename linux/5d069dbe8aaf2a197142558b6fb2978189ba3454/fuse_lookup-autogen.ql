/**
 * @name linux-5d069dbe8aaf2a197142558b6fb2978189ba3454-fuse_lookup
 * @id cpp/linux/5d069dbe8aaf2a197142558b6fb2978189ba3454/fuse-lookup
 * @description linux-5d069dbe8aaf2a197142558b6fb2978189ba3454-fuse_lookup fs/fuse/dir.c
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdir_455, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(FunctionCall).getTarget().hasName("fuse_is_bad")
		and target_0.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdir_455
		and target_0.getThen().(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_PTR")
		and target_0.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(UnaryMinusExpr).getValue()="-5"
		and target_0.getThen().(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(UnaryMinusExpr).getOperand().(Literal).getValue()="5"
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_0))
}

from Function func, Parameter vdir_455
where
not func_0(vdir_455, func)
and vdir_455.getType().hasName("inode *")
and vdir_455.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
