/**
 * @name linux-d9ea761fdd197351890418acd462c51f241014a7-dccp_create_openreq_child
 * @id cpp/linux/d9ea761fdd197351890418acd462c51f241014a7/dccp_create_openreq_child
 * @description linux-d9ea761fdd197351890418acd462c51f241014a7-dccp_create_openreq_child CVE-2017-6074
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vnewsk_87, Variable vnewdp_92) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="dccps_hc_rx_ccid"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnewdp_92
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vnewsk_87
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0")
}

predicate func_1(Variable vnewsk_87, Variable vnewdp_92) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="dccps_hc_tx_ccid"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnewdp_92
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vnewsk_87
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0")
}

predicate func_2(Variable vnewdp_92) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="dccps_service_list"
		and target_2.getQualifier().(VariableAccess).getTarget()=vnewdp_92)
}

from Function func, Variable vnewsk_87, Variable vnewdp_92
where
not func_0(vnewsk_87, vnewdp_92)
and not func_1(vnewsk_87, vnewdp_92)
and vnewsk_87.getType().hasName("sock *")
and vnewdp_92.getType().hasName("dccp_sock *")
and func_2(vnewdp_92)
and vnewsk_87.getParentScope+() = func
and vnewdp_92.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
