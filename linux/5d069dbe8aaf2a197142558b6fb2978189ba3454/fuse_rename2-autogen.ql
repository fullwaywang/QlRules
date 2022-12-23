/**
 * @name linux-5d069dbe8aaf2a197142558b6fb2978189ba3454-fuse_rename2
 * @id cpp/linux/5d069dbe8aaf2a197142558b6fb2978189ba3454/fuse-rename2
 * @description linux-5d069dbe8aaf2a197142558b6fb2978189ba3454-fuse_rename2 fs/fuse/dir.c
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter volddir_896, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(FunctionCall).getTarget().hasName("fuse_is_bad")
		and target_0.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=volddir_896
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-5"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="5"
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_0))
}

predicate func_1(Parameter volddir_896) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("get_fuse_conn")
		and target_1.getArgument(0).(VariableAccess).getTarget()=volddir_896)
}

from Function func, Parameter volddir_896
where
not func_0(volddir_896, func)
and volddir_896.getType().hasName("inode *")
and func_1(volddir_896)
and volddir_896.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
