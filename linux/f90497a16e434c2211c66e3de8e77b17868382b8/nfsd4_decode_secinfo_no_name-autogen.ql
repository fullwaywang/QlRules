/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd4_decode_secinfo_no_name
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/nfsd4-decode-secinfo-no-name
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd4_decode_secinfo_no_name 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vsin_1772, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="sin_exp"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsin_1772
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(1)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(1).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vsin_1772) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="sin_style"
		and target_1.getQualifier().(VariableAccess).getTarget()=vsin_1772)
}

from Function func, Parameter vsin_1772
where
not func_0(vsin_1772, func)
and vsin_1772.getType().hasName("nfsd4_secinfo_no_name *")
and func_1(vsin_1772)
and vsin_1772.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
