import cpp

predicate func_0(Variable vtmplen, Variable vv, Variable vtemp, Variable vlen, Variable vvarname, Variable vvarval) {
	exists(EQExpr target_0 |
		target_0.getType().hasName("int")
		and target_0.getLeftOperand().(FunctionCall).getTarget().hasName("sscanf")
		and target_0.getLeftOperand().(FunctionCall).getType().hasName("int")
		and target_0.getLeftOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="data"
		and target_0.getLeftOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getType().hasName("char *")
		and target_0.getLeftOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vv
		and target_0.getLeftOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%127[^,],%127s"
		and target_0.getLeftOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vvarname
		and target_0.getLeftOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vvarval
		and target_0.getRightOperand().(Literal).getValue()="2"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("curl_msnprintf")
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vtemp
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vlen
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SubExpr).getLeftOperand().(SizeofExprOperator).getExprOperand().(VariableAccess).getTarget()=vtemp
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SubExpr).getRightOperand().(VariableAccess).getTarget()=vlen
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="%c%s%c%s"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vvarname
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(Literal).getValue()="1"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vvarval
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vlen
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vtmplen)
}

predicate func_1(Variable vv, Variable vvarname, Variable vvarval) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("sscanf")
		and target_1.getType().hasName("int")
		and target_1.getArgument(0).(PointerFieldAccess).getTarget().getName()="data"
		and target_1.getArgument(0).(PointerFieldAccess).getType().hasName("char *")
		and target_1.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vv
		and target_1.getArgument(1).(StringLiteral).getValue()="%127[^,],%127s"
		and target_1.getArgument(2).(VariableAccess).getTarget()=vvarname
		and target_1.getArgument(3).(VariableAccess).getTarget()=vvarval)
}

from Function func, Variable vtmplen, Variable vv, Variable vtemp, Variable vlen, Variable vvarname, Variable vvarval
where
not func_0(vtmplen, vv, vtemp, vlen, vvarname, vvarval)
and func_1(vv, vvarname, vvarval)
and vtmplen.getType().hasName("size_t")
and vv.getType().hasName("curl_slist *")
and vtemp.getType().hasName("unsigned char[2048]")
and vlen.getType().hasName("size_t")
and vvarname.getType().hasName("char[128]")
and vvarval.getType().hasName("char[128]")
and vtmplen.getParentScope+() = func
and vv.getParentScope+() = func
and vtemp.getParentScope+() = func
and vlen.getParentScope+() = func
and vvarname.getParentScope+() = func
and vvarval.getParentScope+() = func
select func, vtmplen, vv, vtemp, vlen, vvarname, vvarval
