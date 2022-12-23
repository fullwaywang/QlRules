/**
 * @name linux-271351d255b09e39c7f6437738cba595f9b235be-tipc_data_input
 * @id cpp/linux/271351d255b09e39c7f6437738cba595f9b235be/tipc-data-input
 * @description linux-271351d255b09e39c7f6437738cba595f9b235be-tipc_data_input CVE-2021-43267
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vskb_1268) {
	exists(IfStmt target_0 |
		target_0.getCondition().(ValueFieldAccess).getTarget().getName()="decrypted"
		and target_0.getCondition().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="(unknown field)"
		and target_0.getCondition().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_0.getCondition().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="cb"
		and target_0.getCondition().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vskb_1268
		and target_0.getCondition().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_0.getThen().(BlockStmt).getStmt(1) instanceof ReturnStmt)
}

predicate func_2(Parameter vskb_1268, Parameter vl_1268) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("tipc_crypto_msg_rcv")
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="net"
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_1268
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vskb_1268)
}

predicate func_4(Parameter vskb_1268, Parameter vl_1268) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("skb_queue_tail")
		and target_4.getArgument(0).(PointerFieldAccess).getTarget().getName()="namedq"
		and target_4.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_1268
		and target_4.getArgument(1).(VariableAccess).getTarget()=vskb_1268)
}

from Function func, Parameter vskb_1268, Parameter vl_1268
where
not func_0(vskb_1268)
and func_2(vskb_1268, vl_1268)
and vskb_1268.getType().hasName("sk_buff *")
and func_4(vskb_1268, vl_1268)
and vl_1268.getType().hasName("tipc_link *")
and vskb_1268.getParentScope+() = func
and vl_1268.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
