/**
 * @name linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfs4_get_client_reaplist
 * @id cpp/linux/f90497a16e434c2211c66e3de8e77b17868382b8/nfs4-get-client-reaplist
 * @description linux-f90497a16e434c2211c66e3de8e77b17868382b8-nfs4_get_client_reaplist 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vclp_5869, Parameter vnn_5864) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="cl_state"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vclp_5869
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("atomic_inc")
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="nfsd_courtesy_clients"
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnn_5864
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("atomic_read")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cl_rpc_users"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vclp_5869)
}

predicate func_1(Variable vclp_5869) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="cl_state"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vclp_5869
		and target_1.getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("atomic_read")
		and target_1.getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cl_rpc_users"
		and target_1.getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vclp_5869)
}

predicate func_2(Variable vclp_5869) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="cl_rpc_users"
		and target_2.getQualifier().(VariableAccess).getTarget()=vclp_5869)
}

predicate func_3(Parameter vnn_5864) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="client_lru"
		and target_3.getQualifier().(VariableAccess).getTarget()=vnn_5864)
}

from Function func, Variable vclp_5869, Parameter vnn_5864
where
not func_0(vclp_5869, vnn_5864)
and func_1(vclp_5869)
and vclp_5869.getType().hasName("nfs4_client *")
and func_2(vclp_5869)
and vnn_5864.getType().hasName("nfsd_net *")
and func_3(vnn_5864)
and vclp_5869.getParentScope+() = func
and vnn_5864.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
