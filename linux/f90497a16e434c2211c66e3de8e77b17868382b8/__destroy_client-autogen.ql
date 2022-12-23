/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-__destroy_client
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/--destroy-client
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-__destroy_client 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="2586"
		and not target_0.getValue()="2680"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="2587"
		and not target_1.getValue()="2681"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="2588"
		and not target_2.getValue()="2682"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(Literal target_3 |
		target_3.getValue()="2589"
		and not target_3.getValue()="2683"
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Parameter vclp_2189, Variable vnn_2191, Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(FunctionCall).getTarget().hasName("nfsd4_dec_courtesy_client_count")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnn_2191
		and target_4.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vclp_2189
		and (func.getEntryPoint().(BlockStmt).getStmt(18)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(18).getFollowingStmt()=target_4))
}

predicate func_5(Parameter vclp_2189) {
	exists(PointerFieldAccess target_5 |
		target_5.getTarget().getName()="cl_cb_conn"
		and target_5.getQualifier().(VariableAccess).getTarget()=vclp_2189)
}

predicate func_6(Variable vnn_2191) {
	exists(PointerFieldAccess target_6 |
		target_6.getTarget().getName()="nfs4_client_count"
		and target_6.getQualifier().(VariableAccess).getTarget()=vnn_2191)
}

from Function func, Parameter vclp_2189, Variable vnn_2191
where
func_0(func)
and func_1(func)
and func_2(func)
and func_3(func)
and not func_4(vclp_2189, vnn_2191, func)
and vclp_2189.getType().hasName("nfs4_client *")
and func_5(vclp_2189)
and vnn_2191.getType().hasName("nfsd_net *")
and func_6(vnn_2191)
and vclp_2189.getParentScope+() = func
and vnn_2191.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
