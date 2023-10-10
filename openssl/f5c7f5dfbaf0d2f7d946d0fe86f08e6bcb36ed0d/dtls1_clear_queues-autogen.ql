/**
 * @name openssl-f5c7f5dfbaf0d2f7d946d0fe86f08e6bcb36ed0d-dtls1_clear_queues
 * @id cpp/openssl/f5c7f5dfbaf0d2f7d946d0fe86f08e6bcb36ed0d/dtls1-clear-queues
 * @description openssl-f5c7f5dfbaf0d2f7d946d0fe86f08e6bcb36ed0d-dtls1_clear_queues CVE-2016-2179
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vfrag_119) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("dtls1_hm_fragment_free")
		and not target_0.getTarget().hasName("dtls1_clear_received_buffer")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vfrag_119)
}

predicate func_1(Variable vitem_118) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("pitem_free")
		and not target_1.getTarget().hasName("dtls1_clear_sent_buffer")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vitem_118)
}

predicate func_4(Function func) {
	exists(DeclStmt target_4 |
		target_4.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4)
}

predicate func_5(Function func) {
	exists(DeclStmt target_5 |
		target_5.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_5)
}

predicate func_6(Variable vitem_118, Variable vfrag_119, Parameter vs_116, Function func) {
	exists(WhileStmt target_6 |
		target_6.getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vitem_118
		and target_6.getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("pqueue_pop")
		and target_6.getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="buffered_messages"
		and target_6.getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="d1"
		and target_6.getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_116
		and target_6.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_6.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfrag_119
		and target_6.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="data"
		and target_6.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vitem_118
		and target_6.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr() instanceof FunctionCall
		and target_6.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr() instanceof FunctionCall
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_6)
}

predicate func_9(Variable vitem_118, Variable vfrag_119, Parameter vs_116, Function func) {
	exists(WhileStmt target_9 |
		target_9.getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vitem_118
		and target_9.getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("pqueue_pop")
		and target_9.getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="sent_messages"
		and target_9.getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="d1"
		and target_9.getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_116
		and target_9.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_9.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfrag_119
		and target_9.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="data"
		and target_9.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vitem_118
		and target_9.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("dtls1_hm_fragment_free")
		and target_9.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfrag_119
		and target_9.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("pitem_free")
		and target_9.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vitem_118
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_9)
}

from Function func, Variable vitem_118, Variable vfrag_119, Parameter vs_116
where
func_0(vfrag_119)
and func_1(vitem_118)
and func_4(func)
and func_5(func)
and func_6(vitem_118, vfrag_119, vs_116, func)
and func_9(vitem_118, vfrag_119, vs_116, func)
and vitem_118.getType().hasName("pitem *")
and vfrag_119.getType().hasName("hm_fragment *")
and vs_116.getType().hasName("SSL *")
and vitem_118.getParentScope+() = func
and vfrag_119.getParentScope+() = func
and vs_116.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
