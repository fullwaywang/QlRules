/**
 * @name linux-ca4da5dd1f99fe9c59f1709fb43e818b18ad20e0-__key_link_end
 * @id cpp/linux/ca4da5dd1f99fe9c59f1709fb43e818b18ad20e0/__key_link_end
 * @description linux-ca4da5dd1f99fe9c59f1709fb43e818b18ad20e0-__key_link_end CVE-2015-1333
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vedit_1174) {
	exists(IfStmt target_0 |
		target_0.getCondition() instanceof NotExpr
		and target_0.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vedit_1174)
}

predicate func_1(Parameter vedit_1174, Parameter vkeyring_1172) {
	exists(NotExpr target_1 |
		target_1.getOperand().(PointerFieldAccess).getTarget().getName()="dead_leaf"
		and target_1.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vedit_1174
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vedit_1174
		and target_1.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("key_payload_reserve")
		and target_1.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vkeyring_1172
		and target_1.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="datalen"
		and target_1.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkeyring_1172
		and target_1.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SubExpr).getRightOperand().(Literal).getValue()="4"
		and target_1.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("assoc_array_cancel_edit")
		and target_1.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vedit_1174)
}

predicate func_4(Parameter vedit_1174) {
	exists(LogicalAndExpr target_4 |
		target_4.getAnOperand().(VariableAccess).getTarget()=vedit_1174
		and target_4.getAnOperand() instanceof NotExpr
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("assoc_array_cancel_edit")
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vedit_1174)
}

from Function func, Parameter vedit_1174, Parameter vkeyring_1172
where
not func_0(vedit_1174)
and func_1(vedit_1174, vkeyring_1172)
and func_4(vedit_1174)
and vedit_1174.getType().hasName("assoc_array_edit *")
and vkeyring_1172.getType().hasName("key *")
and vedit_1174.getParentScope+() = func
and vkeyring_1172.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
