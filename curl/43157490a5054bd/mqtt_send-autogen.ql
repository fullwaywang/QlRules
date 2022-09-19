import cpp

predicate func_0(Parameter vlen, Variable vmq, Variable vn) {
	exists(BlockStmt target_0 |
		target_0.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getType().hasName("char *")
		and target_0.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="sendleftovers"
		and target_0.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getType().hasName("char *")
		and target_0.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmq
		and target_0.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getType().hasName("size_t")
		and target_0.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="nsend"
		and target_0.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getType().hasName("size_t")
		and target_0.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmq
		and target_0.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getParent().(IfStmt).getCondition().(NEExpr).getType().hasName("int")
		and target_0.getParent().(IfStmt).getCondition().(NEExpr).getLeftOperand().(VariableAccess).getTarget()=vlen
		and target_0.getParent().(IfStmt).getCondition().(NEExpr).getRightOperand().(VariableAccess).getTarget()=vn)
}

from Function func, Parameter vlen, Variable vmq, Variable vn
where
not func_0(vlen, vmq, vn)
and vlen.getType().hasName("size_t")
and vmq.getType().hasName("MQTT *")
and vn.getType().hasName("ssize_t")
and vlen.getParentScope+() = func
and vmq.getParentScope+() = func
and vn.getParentScope+() = func
select func, vlen, vmq, vn
