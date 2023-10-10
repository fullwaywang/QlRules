/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd4_decode_sequence
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/nfsd4-decode-sequence
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd4_decode_sequence 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vseq_1781, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="status_flags"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vseq_1781
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vseq_1781) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="cachethis"
		and target_1.getQualifier().(VariableAccess).getTarget()=vseq_1781)
}

from Function func, Parameter vseq_1781
where
not func_0(vseq_1781, func)
and vseq_1781.getType().hasName("nfsd4_sequence *")
and func_1(vseq_1781)
and vseq_1781.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
