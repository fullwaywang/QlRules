/**
 * @name openssl-f5c7f5dfbaf0d2f7d946d0fe86f08e6bcb36ed0d-dtls1_retrieve_buffered_fragment
 * @id cpp/openssl/f5c7f5dfbaf0d2f7d946d0fe86f08e6bcb36ed0d/dtls1-retrieve-buffered-fragment
 * @description openssl-f5c7f5dfbaf0d2f7d946d0fe86f08e6bcb36ed0d-dtls1_retrieve_buffered_fragment CVE-2016-2179
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_432, Variable vitem_440, Variable vfrag_441, Function func) {
	exists(DoStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vitem_440
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getStmt().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_0.getStmt().(BlockStmt).getStmt(1) instanceof IfStmt
		and target_0.getStmt().(BlockStmt).getStmt(2) instanceof ExprStmt
		and target_0.getStmt().(BlockStmt).getStmt(3).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="seq"
		and target_0.getStmt().(BlockStmt).getStmt(3).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="msg_header"
		and target_0.getStmt().(BlockStmt).getStmt(3).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfrag_441
		and target_0.getStmt().(BlockStmt).getStmt(3).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="handshake_read_seq"
		and target_0.getStmt().(BlockStmt).getStmt(3).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="d1"
		and target_0.getStmt().(BlockStmt).getStmt(3).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_432
		and target_0.getStmt().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("pqueue_pop")
		and target_0.getStmt().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="buffered_messages"
		and target_0.getStmt().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("dtls1_hm_fragment_free")
		and target_0.getStmt().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfrag_441
		and target_0.getStmt().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("pitem_free")
		and target_0.getStmt().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vitem_440
		and target_0.getStmt().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vitem_440
		and target_0.getStmt().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getStmt().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfrag_441
		and target_0.getStmt().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_0))
}

predicate func_7(Parameter vs_432, Variable vitem_440, Function func) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vitem_440
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("pqueue_peek")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="buffered_messages"
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="d1"
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_432
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_7)
}

predicate func_8(Variable vitem_440, Function func) {
	exists(IfStmt target_8 |
		target_8.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vitem_440
		and target_8.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_8.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_8)
}

predicate func_9(Variable vitem_440, Variable vfrag_441, Function func) {
	exists(ExprStmt target_9 |
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfrag_441
		and target_9.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="data"
		and target_9.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vitem_440
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_9)
}

from Function func, Parameter vs_432, Variable vitem_440, Variable vfrag_441
where
not func_0(vs_432, vitem_440, vfrag_441, func)
and func_7(vs_432, vitem_440, func)
and func_8(vitem_440, func)
and func_9(vitem_440, vfrag_441, func)
and vs_432.getType().hasName("SSL *")
and vitem_440.getType().hasName("pitem *")
and vfrag_441.getType().hasName("hm_fragment *")
and vs_432.getParentScope+() = func
and vitem_440.getParentScope+() = func
and vfrag_441.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
