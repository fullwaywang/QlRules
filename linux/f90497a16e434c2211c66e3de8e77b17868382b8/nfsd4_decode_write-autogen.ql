/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd4_decode_write
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/nfsd4-decode-write
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd4_decode_write 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vwrite_1393, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="wr_bytes_written"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwrite_1393
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vwrite_1393, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="wr_how_written"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwrite_1393
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_1))
}

predicate func_2(Parameter vwrite_1393, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("__memset")
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="wr_verifier"
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwrite_1393
		and target_2.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_2.getExpr().(FunctionCall).getArgument(2).(SizeofExprOperator).getValue()="8"
		and target_2.getExpr().(FunctionCall).getArgument(2).(SizeofExprOperator).getExprOperand().(PointerFieldAccess).getTarget().getName()="wr_verifier"
		and target_2.getExpr().(FunctionCall).getArgument(2).(SizeofExprOperator).getExprOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwrite_1393
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_2))
}

predicate func_3(Parameter vwrite_1393) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="wr_buflen"
		and target_3.getQualifier().(VariableAccess).getTarget()=vwrite_1393)
}

from Function func, Parameter vwrite_1393
where
not func_0(vwrite_1393, func)
and not func_1(vwrite_1393, func)
and not func_2(vwrite_1393, func)
and vwrite_1393.getType().hasName("nfsd4_write *")
and func_3(vwrite_1393)
and vwrite_1393.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
