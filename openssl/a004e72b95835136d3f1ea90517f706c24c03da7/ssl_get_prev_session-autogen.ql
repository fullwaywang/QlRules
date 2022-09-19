import cpp

predicate func_0(Parameter vlimit, Variable vfatal, Parameter vlen, Parameter vsession_id) {
	exists(LTExpr target_0 |
		target_0.getType().hasName("int")
		and target_0.getLesserOperand().(PointerDiffExpr).getType().hasName("long")
		and target_0.getLesserOperand().(PointerDiffExpr).getLeftOperand().(VariableAccess).getTarget()=vlimit
		and target_0.getLesserOperand().(PointerDiffExpr).getRightOperand().(VariableAccess).getTarget()=vsession_id
		and target_0.getGreaterOperand().(VariableAccess).getTarget()=vlen
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfatal
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1")
}

predicate func_3(Variable vfatal) {
	exists(VariableAccess target_3 |
		target_3.getParent().(GTExpr).getGreaterOperand() instanceof PointerAddExpr
		and target_3.getParent().(GTExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfatal
		and target_3.getParent().(GTExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1")
}

predicate func_4(Parameter vlimit, Variable vfatal, Parameter vlen, Parameter vsession_id) {
	exists(GTExpr target_4 |
		target_4.getType().hasName("int")
		and target_4.getGreaterOperand().(PointerAddExpr).getType().hasName("unsigned char *")
		and target_4.getGreaterOperand().(PointerAddExpr).getLeftOperand().(VariableAccess).getTarget()=vsession_id
		and target_4.getGreaterOperand().(PointerAddExpr).getRightOperand().(VariableAccess).getTarget()=vlen
		and target_4.getLesserOperand().(VariableAccess).getTarget()=vlimit
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfatal
		and target_4.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1")
}

from Function func, Parameter vlimit, Variable vfatal, Parameter vlen, Parameter vsession_id
where
not func_0(vlimit, vfatal, vlen, vsession_id)
and func_3(vfatal)
and func_4(vlimit, vfatal, vlen, vsession_id)
and vlimit.getType().hasName("const unsigned char *")
and vfatal.getType().hasName("int")
and vlen.getType().hasName("int")
and vsession_id.getType().hasName("unsigned char *")
and vlimit.getParentScope+() = func
and vfatal.getParentScope+() = func
and vlen.getParentScope+() = func
and vsession_id.getParentScope+() = func
select func, vlimit, vfatal, vlen, vsession_id
