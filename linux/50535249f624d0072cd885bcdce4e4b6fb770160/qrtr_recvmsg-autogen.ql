/**
 * @name linux-50535249f624d0072cd885bcdce4e4b6fb770160-qrtr_recvmsg
 * @id cpp/linux/50535249f624d0072cd885bcdce4e4b6fb770160/qrtr-recvmsg
 * @description linux-50535249f624d0072cd885bcdce4e4b6fb770160-qrtr_recvmsg 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vaddr_1028) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("__memset")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vaddr_1028
		and target_0.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_0.getExpr().(FunctionCall).getArgument(2).(SizeofExprOperator).getValue()="12"
		and target_0.getExpr().(FunctionCall).getArgument(2).(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vaddr_1028
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vaddr_1028)
}

predicate func_1(Parameter vmsg_1025, Variable vaddr_1028, Variable vcb_1031, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(VariableAccess).getTarget()=vaddr_1028
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="sq_family"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vaddr_1028
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="42"
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="sq_node"
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vaddr_1028
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="src_node"
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcb_1031
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="sq_port"
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vaddr_1028
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="src_port"
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcb_1031
		and target_1.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="msg_namelen"
		and target_1.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmsg_1025
		and target_1.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vaddr_1028
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1)
}

from Function func, Parameter vmsg_1025, Variable vaddr_1028, Variable vcb_1031
where
not func_0(vaddr_1028)
and vaddr_1028.getType().hasName("sockaddr_qrtr *")
and func_1(vmsg_1025, vaddr_1028, vcb_1031, func)
and vcb_1031.getType().hasName("qrtr_cb *")
and vmsg_1025.getParentScope+() = func
and vaddr_1028.getParentScope+() = func
and vcb_1031.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
