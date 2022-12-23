/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-get_client_locked
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/get-client-locked
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-get_client_locked 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="2489"
		and not target_0.getValue()="2573"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="2490"
		and not target_1.getValue()="2574"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Parameter vclp_163, Variable vnn_165, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("nfsd4_dec_courtesy_client_count")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnn_165
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vclp_163
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_2))
}

predicate func_3(Parameter vclp_163) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="cl_rpc_users"
		and target_3.getQualifier().(VariableAccess).getTarget()=vclp_163)
}

predicate func_4(Variable vnn_165) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="client_lock"
		and target_4.getQualifier().(VariableAccess).getTarget()=vnn_165)
}

from Function func, Parameter vclp_163, Variable vnn_165
where
func_0(func)
and func_1(func)
and not func_2(vclp_163, vnn_165, func)
and vclp_163.getType().hasName("nfs4_client *")
and func_3(vclp_163)
and vnn_165.getType().hasName("nfsd_net *")
and func_4(vnn_165)
and vclp_163.getParentScope+() = func
and vnn_165.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
