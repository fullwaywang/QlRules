/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-renew_client_locked
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/renew-client-locked
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-renew_client_locked 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="2491"
		and not target_0.getValue()="2575"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="2492"
		and not target_1.getValue()="2576"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Variable vnn_180, Parameter vclp_178, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("nfsd4_dec_courtesy_client_count")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnn_180
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vclp_178
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_2))
}

predicate func_3(Variable vnn_180) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="client_lru"
		and target_3.getQualifier().(VariableAccess).getTarget()=vnn_180)
}

predicate func_4(Parameter vclp_178) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="cl_time"
		and target_4.getQualifier().(VariableAccess).getTarget()=vclp_178)
}

from Function func, Variable vnn_180, Parameter vclp_178
where
func_0(func)
and func_1(func)
and not func_2(vnn_180, vclp_178, func)
and vnn_180.getType().hasName("nfsd_net *")
and func_3(vnn_180)
and vclp_178.getType().hasName("nfs4_client *")
and func_4(vclp_178)
and vnn_180.getParentScope+() = func
and vclp_178.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
