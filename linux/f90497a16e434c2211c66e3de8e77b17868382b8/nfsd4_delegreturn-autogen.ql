/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd4_delegreturn
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/nfsd4-delegreturn
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd4_delegreturn 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vcstate_6757, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("wake_up_var")
		and target_0.getExpr().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("d_inode")
		and target_0.getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="fh_dentry"
		and target_0.getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="current_fh"
		and target_0.getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcstate_6757
		and (func.getEntryPoint().(BlockStmt).getStmt(12)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(12).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vcstate_6757) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("nfsd4_has_session")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vcstate_6757)
}

from Function func, Parameter vcstate_6757
where
not func_0(vcstate_6757, func)
and vcstate_6757.getType().hasName("nfsd4_compound_state *")
and func_1(vcstate_6757)
and vcstate_6757.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
