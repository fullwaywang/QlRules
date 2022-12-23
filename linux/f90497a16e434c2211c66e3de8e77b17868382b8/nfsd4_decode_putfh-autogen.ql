/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd4_decode_putfh
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/nfsd4-decode-putfh
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd4_decode_putfh 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vputfh_1204, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="no_verify"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vputfh_1204
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vputfh_1204) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="pf_fhval"
		and target_1.getQualifier().(VariableAccess).getTarget()=vputfh_1204)
}

from Function func, Parameter vputfh_1204
where
not func_0(vputfh_1204, func)
and vputfh_1204.getType().hasName("nfsd4_putfh *")
and func_1(vputfh_1204)
and vputfh_1204.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
