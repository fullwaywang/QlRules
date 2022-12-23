/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd4_decode_commit
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/nfsd4-decode-commit
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd4_decode_commit 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vcommit_788, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("__memset")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="co_verf"
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcommit_788
		and target_0.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_0.getExpr().(FunctionCall).getArgument(2).(SizeofExprOperator).getValue()="8"
		and target_0.getExpr().(FunctionCall).getArgument(2).(SizeofExprOperator).getExprOperand().(PointerFieldAccess).getTarget().getName()="co_verf"
		and target_0.getExpr().(FunctionCall).getArgument(2).(SizeofExprOperator).getExprOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcommit_788
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vcommit_788) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="co_count"
		and target_1.getQualifier().(VariableAccess).getTarget()=vcommit_788)
}

from Function func, Parameter vcommit_788
where
not func_0(vcommit_788, func)
and vcommit_788.getType().hasName("nfsd4_commit *")
and func_1(vcommit_788)
and vcommit_788.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
