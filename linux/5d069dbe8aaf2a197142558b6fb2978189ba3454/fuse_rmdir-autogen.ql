/**
 * @name linux-5d069dbe8aaf2a197142558b6fb2978189ba3454-fuse_rmdir
 * @id cpp/linux/5d069dbe8aaf2a197142558b6fb2978189ba3454/fuse-rmdir
 * @description linux-5d069dbe8aaf2a197142558b6fb2978189ba3454-fuse_rmdir fs/fuse/dir.c
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdir_819, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(FunctionCall).getTarget().hasName("fuse_is_bad")
		and target_0.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdir_819
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-5"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="5"
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vdir_819) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("get_fuse_mount")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vdir_819)
}

from Function func, Parameter vdir_819
where
not func_0(vdir_819, func)
and vdir_819.getType().hasName("inode *")
and func_1(vdir_819)
and vdir_819.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
