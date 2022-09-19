import cpp

predicate func_3(Function func) {
	exists(Literal target_3 |
		target_3.getValue()="8"
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Parameter vin, Parameter vlen, Variable vi, Parameter vc) {
	exists(AddExpr target_4 |
		target_4.getType().hasName("unsigned long")
		and target_4.getLeftOperand().(VariableAccess).getTarget()=vi
		and target_4.getRightOperand().(VariableAccess).getTarget()=vlen
		and target_4.getParent().(LTExpr).getGreaterOperand() instanceof Literal
		and target_4.getParent().(LTExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_4.getParent().(LTExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_4.getParent().(LTExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc
		and target_4.getParent().(LTExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi
		and target_4.getParent().(LTExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vin
		and target_4.getParent().(LTExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlen
		and target_4.getParent().(LTExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="num"
		and target_4.getParent().(LTExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc
		and target_4.getParent().(LTExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vlen
		and target_4.getParent().(LTExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(Literal).getValue()="1")
}

from Function func, Parameter vin, Parameter vlen, Variable vi, Parameter vc
where
func_3(func)
and func_4(vin, vlen, vi, vc)
and vin.getType().hasName("const unsigned char *")
and vlen.getType().hasName("size_t")
and vi.getType().hasName("size_t")
and vc.getType().hasName("MDC2_CTX *")
and vin.getParentScope+() = func
and vlen.getParentScope+() = func
and vi.getParentScope+() = func
and vc.getParentScope+() = func
select func, vin, vlen, vi, vc
