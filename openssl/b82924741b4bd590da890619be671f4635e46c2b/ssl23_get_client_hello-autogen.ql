import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="565"
		and not target_0.getValue()="566"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="600"
		and not target_1.getValue()="602"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Variable vtype) {
	exists(DeclStmt target_2 |
		target_2.getDeclarationEntry(0).(VariableDeclarationEntry).getType().hasName("const SSL_METHOD *")
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getType().hasName("int")
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getLeftOperand().(EQExpr).getLeftOperand().(VariableAccess).getTarget()=vtype
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getLeftOperand().(EQExpr).getRightOperand().(Literal).getValue()="2"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getRightOperand().(EQExpr).getLeftOperand().(VariableAccess).getTarget()=vtype
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getRightOperand().(EQExpr).getRightOperand().(Literal).getValue()="3")
}

predicate func_3(Parameter vs) {
	exists(AssignExpr target_3 |
		target_3.getType().hasName("const SSL_METHOD *")
		and target_3.getRValue().(FunctionCall).getTarget().hasName("ssl23_get_server_method")
		and target_3.getRValue().(FunctionCall).getType().hasName("SSL_METHOD *")
		and target_3.getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="version"
		and target_3.getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getType().hasName("int")
		and target_3.getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs)
}

predicate func_4(Function func) {
	exists(VariableAccess target_4 |
		target_4.getParent().(EQExpr).getRightOperand().(Literal).getValue()="0"
		and target_4.getParent().(EQExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_4.getParent().(EQExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="20"
		and target_4.getParent().(EQExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="118"
		and target_4.getParent().(EQExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="258"
		and target_4.getParent().(EQExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="s23_srvr.c"
		and target_4.getParent().(EQExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="566"
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Variable vtype, Parameter vs) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getType().hasName("SSL_METHOD *")
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="method"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getType().hasName("SSL_METHOD *")
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getType().hasName("int")
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getLeftOperand().(EQExpr).getLeftOperand().(VariableAccess).getTarget()=vtype
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getLeftOperand().(EQExpr).getRightOperand().(Literal).getValue()="2"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getRightOperand().(EQExpr).getLeftOperand().(VariableAccess).getTarget()=vtype
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getRightOperand().(EQExpr).getRightOperand().(Literal).getValue()="3")
}

predicate func_7(Parameter vs) {
	exists(FunctionCall target_7 |
		target_7.getTarget().hasName("ssl23_get_server_method")
		and target_7.getType().hasName("SSL_METHOD *")
		and target_7.getArgument(0).(PointerFieldAccess).getTarget().getName()="version"
		and target_7.getArgument(0).(PointerFieldAccess).getType().hasName("int")
		and target_7.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs)
}

predicate func_8(Parameter vs) {
	exists(PointerFieldAccess target_8 |
		target_8.getTarget().getName()="method"
		and target_8.getType().hasName("SSL_METHOD *")
		and target_8.getQualifier().(VariableAccess).getTarget()=vs)
}

from Function func, Variable vtype, Parameter vs
where
func_0(func)
and func_1(func)
and not func_2(vtype)
and not func_3(vs)
and not func_4(func)
and not func_5(vtype, vs)
and func_7(vs)
and func_8(vs)
and vtype.getType().hasName("int")
and vs.getType().hasName("SSL *")
and vtype.getParentScope+() = func
and vs.getParentScope+() = func
select func, vtype, vs
