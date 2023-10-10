/**
 * @name linux-5d069dbe8aaf2a197142558b6fb2978189ba3454-create_new_entry
 * @id cpp/linux/5d069dbe8aaf2a197142558b6fb2978189ba3454/create-new-entry
 * @description linux-5d069dbe8aaf2a197142558b6fb2978189ba3454-create_new_entry fs/fuse/dir.c
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdir_653, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(FunctionCall).getTarget().hasName("fuse_is_bad")
		and target_0.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdir_653
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-5"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="5"
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_0))
}

from Function func, Parameter vdir_653
where
not func_0(vdir_653, func)
and vdir_653.getType().hasName("inode *")
and vdir_653.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
