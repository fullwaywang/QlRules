/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd4_cb_recall_done
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/nfsd4-cb-recall-done
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd4_cb_recall_done 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vdp_4744, Parameter vtask_4742, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("trace_nfsd_cb_recall_done")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="sc_stateid"
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dl_stid"
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdp_4744
		and target_0.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtask_4742
		and (func.getEntryPoint().(BlockStmt).getStmt(1)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(1).getFollowingStmt()=target_0))
}

from Function func, Variable vdp_4744, Parameter vtask_4742
where
not func_0(vdp_4744, vtask_4742, func)
and vdp_4744.getType().hasName("nfs4_delegation *")
and vtask_4742.getType().hasName("rpc_task *")
and vdp_4744.getParentScope+() = func
and vtask_4742.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
