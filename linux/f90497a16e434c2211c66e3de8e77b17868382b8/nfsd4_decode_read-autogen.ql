/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd4_decode_read
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/nfsd4-decode-read
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd4_decode_read 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vread_1231, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("__memset")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vread_1231
		and target_0.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_0.getExpr().(FunctionCall).getArgument(2).(SizeofExprOperator).getValue()="64"
		and target_0.getExpr().(FunctionCall).getArgument(2).(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vread_1231
		and (func.getEntryPoint().(BlockStmt).getStmt(1)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(1).getFollowingStmt()=target_0))
}

from Function func, Parameter vread_1231
where
not func_0(vread_1231, func)
and vread_1231.getType().hasName("nfsd4_read *")
and vread_1231.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
