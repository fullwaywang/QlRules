/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd4_cb_layout_done
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/nfsd4-cb-layout-done
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd4_cb_layout_done 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtask_653, Variable vls_655, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("trace_nfsd_cb_layout_done")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="sc_stateid"
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ls_stid"
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vls_655
		and target_0.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtask_653
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_0))
}

from Function func, Parameter vtask_653, Variable vls_655
where
not func_0(vtask_653, vls_655, func)
and vtask_653.getType().hasName("rpc_task *")
and vls_655.getType().hasName("nfs4_layout_stateid *")
and vtask_653.getParentScope+() = func
and vls_655.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
