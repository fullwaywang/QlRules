import cpp

predicate func_0(Variable vfrag) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("dtls1_hm_fragment_free")
		and not target_0.getTarget().hasName("dtls1_clear_received_buffer")
		and target_0.getType().hasName("void")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vfrag)
}

predicate func_1(Variable vitem) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("pitem_free")
		and not target_1.getTarget().hasName("dtls1_clear_sent_buffer")
		and target_1.getType().hasName("void")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vitem)
}

predicate func_4(Function func) {
	exists(DeclStmt target_4 |
		target_4.getDeclarationEntry(0).(VariableDeclarationEntry).getType().hasName("pitem *")
		and target_4.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4)
}

predicate func_5(Function func) {
	exists(DeclStmt target_5 |
		target_5.getDeclarationEntry(0).(VariableDeclarationEntry).getType().hasName("hm_fragment *")
		and target_5.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_5)
}

predicate func_6(Parameter vs, Variable vitem, Variable vfrag, Function func) {
	exists(WhileStmt target_6 |
		target_6.getCondition().(NEExpr).getType().hasName("int")
		and target_6.getCondition().(NEExpr).getLeftOperand().(AssignExpr).getType().hasName("pitem *")
		and target_6.getCondition().(NEExpr).getLeftOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vitem
		and target_6.getCondition().(NEExpr).getLeftOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("pqueue_pop")
		and target_6.getCondition().(NEExpr).getLeftOperand().(AssignExpr).getRValue().(FunctionCall).getType().hasName("pitem *")
		and target_6.getCondition().(NEExpr).getLeftOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="buffered_messages"
		and target_6.getCondition().(NEExpr).getLeftOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="d1"
		and target_6.getCondition().(NEExpr).getLeftOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs
		and target_6.getCondition().(NEExpr).getRightOperand().(Literal).getValue()="0"
		and target_6.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getType().hasName("hm_fragment *")
		and target_6.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfrag
		and target_6.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="data"
		and target_6.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vitem
		and target_6.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr() instanceof FunctionCall
		and target_6.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr() instanceof FunctionCall
		and target_6.getEnclosingFunction() = func
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_6)
}

predicate func_8(Parameter vs, Variable vitem, Variable vfrag, Function func) {
	exists(WhileStmt target_8 |
		target_8.getCondition().(NEExpr).getType().hasName("int")
		and target_8.getCondition().(NEExpr).getLeftOperand().(AssignExpr).getType().hasName("pitem *")
		and target_8.getCondition().(NEExpr).getLeftOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vitem
		and target_8.getCondition().(NEExpr).getLeftOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("pqueue_pop")
		and target_8.getCondition().(NEExpr).getLeftOperand().(AssignExpr).getRValue().(FunctionCall).getType().hasName("pitem *")
		and target_8.getCondition().(NEExpr).getLeftOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="sent_messages"
		and target_8.getCondition().(NEExpr).getLeftOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="d1"
		and target_8.getCondition().(NEExpr).getLeftOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs
		and target_8.getCondition().(NEExpr).getRightOperand().(Literal).getValue()="0"
		and target_8.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getType().hasName("hm_fragment *")
		and target_8.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfrag
		and target_8.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="data"
		and target_8.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vitem
		and target_8.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("dtls1_hm_fragment_free")
		and target_8.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getType().hasName("void")
		and target_8.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfrag
		and target_8.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("pitem_free")
		and target_8.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getType().hasName("void")
		and target_8.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vitem
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_8)
}

from Function func, Parameter vs, Variable vitem, Variable vfrag
where
func_0(vfrag)
and func_1(vitem)
and func_4(func)
and func_5(func)
and func_6(vs, vitem, vfrag, func)
and func_8(vs, vitem, vfrag, func)
and vs.getType().hasName("SSL *")
and vitem.getType().hasName("pitem *")
and vfrag.getType().hasName("hm_fragment *")
and vs.getParentScope+() = func
and vitem.getParentScope+() = func
and vfrag.getParentScope+() = func
select func, vs, vitem, vfrag
