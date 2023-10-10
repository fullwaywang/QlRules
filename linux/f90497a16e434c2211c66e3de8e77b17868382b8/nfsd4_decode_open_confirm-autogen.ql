/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd4_decode_open_confirm
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/nfsd4-decode-open-confirm
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfsd4_decode_open_confirm 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vopen_conf_1169, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("__memset")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="oc_resp_stateid"
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vopen_conf_1169
		and target_0.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_0.getExpr().(FunctionCall).getArgument(2).(SizeofExprOperator).getValue()="16"
		and target_0.getExpr().(FunctionCall).getArgument(2).(SizeofExprOperator).getExprOperand().(PointerFieldAccess).getTarget().getName()="oc_resp_stateid"
		and target_0.getExpr().(FunctionCall).getArgument(2).(SizeofExprOperator).getExprOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vopen_conf_1169
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vopen_conf_1169) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="oc_seqid"
		and target_1.getQualifier().(VariableAccess).getTarget()=vopen_conf_1169)
}

from Function func, Parameter vopen_conf_1169
where
not func_0(vopen_conf_1169, func)
and vopen_conf_1169.getType().hasName("nfsd4_open_confirm *")
and func_1(vopen_conf_1169)
and vopen_conf_1169.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
