/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd_init_net
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/nfsd-init-net
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd_init_net 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vnn_1474, Variable vretval_1473) {
	exists(AssignExpr target_0 |
		target_0.getLValue().(VariableAccess).getTarget()=vretval_1473
		and target_0.getRValue().(FunctionCall).getTarget().hasName("nfsd4_init_leases_net")
		and target_0.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnn_1474)
}

predicate func_1(Variable vretval_1473, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(VariableAccess).getTarget()=vretval_1473
		and target_1.getThen().(GotoStmt).toString() = "goto ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_1))
}

predicate func_3(Variable vnn_1474) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("nfsd4_init_leases_net")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vnn_1474)
}

from Function func, Variable vnn_1474, Variable vretval_1473
where
not func_0(vnn_1474, vretval_1473)
and not func_1(vretval_1473, func)
and func_3(vnn_1474)
and vnn_1474.getType().hasName("nfsd_net *")
and vretval_1473.getType().hasName("int")
and vnn_1474.getParentScope+() = func
and vretval_1473.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
