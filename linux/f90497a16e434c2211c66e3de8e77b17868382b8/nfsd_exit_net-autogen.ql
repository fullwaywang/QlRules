/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd_exit_net
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/nfsd-exit-net
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd_exit_net 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vnn_1504, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("nfsd4_leases_net_shutdown")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnn_1504
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_0))
}

predicate func_1(Variable vnn_1504) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("nfsd_reply_cache_shutdown")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vnn_1504)
}

from Function func, Variable vnn_1504
where
not func_0(vnn_1504, func)
and vnn_1504.getType().hasName("nfsd_net *")
and func_1(vnn_1504)
and vnn_1504.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
