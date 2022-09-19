import cpp

predicate func_0(Parameter vs, Variable vitem, Variable vfrag, Function func) {
	exists(DoStmt target_0 |
		target_0.getCondition().(EQExpr).getType().hasName("int")
		and target_0.getCondition().(EQExpr).getLeftOperand().(VariableAccess).getTarget()=vitem
		and target_0.getCondition().(EQExpr).getRightOperand().(Literal).getValue()="0"
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getType().hasName("pitem *")
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vitem
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("pqueue_peek")
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="buffered_messages"
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="d1"
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EQExpr).getType().hasName("int")
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EQExpr).getLeftOperand().(VariableAccess).getTarget()=vitem
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EQExpr).getRightOperand().(Literal).getValue()="0"
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_0.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getType().hasName("hm_fragment *")
		and target_0.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfrag
		and target_0.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="data"
		and target_0.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vitem
		and target_0.getStmt().(BlockStmt).getStmt(3).(IfStmt).getCondition().(LTExpr).getType().hasName("int")
		and target_0.getStmt().(BlockStmt).getStmt(3).(IfStmt).getCondition().(LTExpr).getLesserOperand().(ValueFieldAccess).getTarget().getName()="seq"
		and target_0.getStmt().(BlockStmt).getStmt(3).(IfStmt).getCondition().(LTExpr).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="msg_header"
		and target_0.getStmt().(BlockStmt).getStmt(3).(IfStmt).getCondition().(LTExpr).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfrag
		and target_0.getStmt().(BlockStmt).getStmt(3).(IfStmt).getCondition().(LTExpr).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="handshake_read_seq"
		and target_0.getStmt().(BlockStmt).getStmt(3).(IfStmt).getCondition().(LTExpr).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="d1"
		and target_0.getStmt().(BlockStmt).getStmt(3).(IfStmt).getCondition().(LTExpr).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs
		and target_0.getStmt().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("pqueue_pop")
		and target_0.getStmt().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="buffered_messages"
		and target_0.getStmt().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="d1"
		and target_0.getStmt().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs
		and target_0.getStmt().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("dtls1_hm_fragment_free")
		and target_0.getStmt().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfrag
		and target_0.getStmt().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("pitem_free")
		and target_0.getStmt().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vitem
		and target_0.getStmt().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vitem
		and target_0.getStmt().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getStmt().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfrag
		and target_0.getStmt().(BlockStmt).getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0)
}

predicate func_1(Parameter vs, Variable vitem, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getType().hasName("pitem *")
		and target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vitem
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("pqueue_peek")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getType().hasName("pitem *")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="buffered_messages"
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getType().hasName("pqueue *")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="d1"
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1)
}

predicate func_2(Variable vitem, Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition().(EQExpr).getType().hasName("int")
		and target_2.getCondition().(EQExpr).getLeftOperand().(VariableAccess).getTarget()=vitem
		and target_2.getCondition().(EQExpr).getRightOperand().(Literal).getValue()="0"
		and target_2.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2)
}

predicate func_3(Variable vitem, Variable vfrag, Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getType().hasName("hm_fragment *")
		and target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfrag
		and target_3.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="data"
		and target_3.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getType().hasName("void *")
		and target_3.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vitem
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3)
}

from Function func, Parameter vs, Variable vitem, Variable vfrag
where
not func_0(vs, vitem, vfrag, func)
and func_1(vs, vitem, func)
and func_2(vitem, func)
and func_3(vitem, vfrag, func)
and vs.getType().hasName("SSL *")
and vitem.getType().hasName("pitem *")
and vfrag.getType().hasName("hm_fragment *")
and vs.getParentScope+() = func
and vitem.getParentScope+() = func
and vfrag.getParentScope+() = func
select func, vs, vitem, vfrag
