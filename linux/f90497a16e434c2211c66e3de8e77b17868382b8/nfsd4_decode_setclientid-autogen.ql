/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd4_decode_setclientid
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/nfsd4-decode-setclientid
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd4_decode_setclientid 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vsetclientid_1312, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("__memset")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsetclientid_1312
		and target_0.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_0.getExpr().(FunctionCall).getArgument(2).(SizeofExprOperator).getValue()="80"
		and target_0.getExpr().(FunctionCall).getArgument(2).(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsetclientid_1312
		and (func.getEntryPoint().(BlockStmt).getStmt(1)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(1).getFollowingStmt()=target_0))
}

from Function func, Parameter vsetclientid_1312
where
not func_0(vsetclientid_1312, func)
and vsetclientid_1312.getType().hasName("nfsd4_setclientid *")
and vsetclientid_1312.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
