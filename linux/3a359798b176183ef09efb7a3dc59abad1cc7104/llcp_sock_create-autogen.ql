/**
 * @name linux-3a359798b176183ef09efb7a3dc59abad1cc7104-llcp_sock_create
 * @id cpp/linux/3a359798b176183ef09efb7a3dc59abad1cc7104/llcp_sock_create
 * @description linux-3a359798b176183ef09efb7a3dc59abad1cc7104-llcp_sock_create 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vsock_995) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("capable")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(Literal).getValue()="13"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="1"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsock_995)
}

predicate func_1(Parameter vsock_995, Variable vllcp_rawsock_ops) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ops"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsock_995
		and target_1.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vllcp_rawsock_ops
		and target_1.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_1.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsock_995)
}

predicate func_2(Variable vllcp_sock_ops, Parameter vsock_995) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ops"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsock_995
		and target_2.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vllcp_sock_ops
		and target_2.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_2.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsock_995)
}

from Function func, Variable vllcp_sock_ops, Parameter vsock_995, Variable vllcp_rawsock_ops
where
not func_0(vsock_995)
and func_1(vsock_995, vllcp_rawsock_ops)
and func_2(vllcp_sock_ops, vsock_995)
and vllcp_sock_ops.getType().hasName("const proto_ops")
and vsock_995.getType().hasName("socket *")
and vllcp_rawsock_ops.getType().hasName("const proto_ops")
and not vllcp_sock_ops.getParentScope+() = func
and vsock_995.getParentScope+() = func
and not vllcp_rawsock_ops.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
