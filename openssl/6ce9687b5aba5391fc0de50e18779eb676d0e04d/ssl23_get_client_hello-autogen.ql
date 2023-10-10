/**
 * @name openssl-6ce9687b5aba5391fc0de50e18779eb676d0e04d-ssl23_get_client_hello
 * @id cpp/openssl/6ce9687b5aba5391fc0de50e18779eb676d0e04d/ssl23-get-client-hello
 * @description openssl-6ce9687b5aba5391fc0de50e18779eb676d0e04d-ssl23_get_client_hello CVE-2014-3569
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vtype_260) {
	exists(DeclStmt target_0 |
		target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof PointerType
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtype_260
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="2"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtype_260
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="3")
}

predicate func_3(Variable vtype_260, Parameter vs_240) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="method"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_240
		and target_3.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("const SSL_METHOD *")
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtype_260
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="2"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtype_260
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="3")
}

predicate func_4(Parameter vs_240) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="method"
		and target_4.getQualifier().(VariableAccess).getTarget()=vs_240
		and target_4.getParent().(AssignExpr).getLValue() = target_4
		and target_4.getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ssl23_get_server_method")
		and target_4.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="version"
		and target_4.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_240)
}

predicate func_5(Parameter vs_240) {
	exists(PointerFieldAccess target_5 |
		target_5.getTarget().getName()="method"
		and target_5.getQualifier().(VariableAccess).getTarget()=vs_240
		and target_5.getParent().(EQExpr).getAnOperand().(Literal).getValue()="0"
		and target_5.getParent().(EQExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_5.getParent().(EQExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_5.getParent().(EQExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_5.getParent().(EQExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_5.getParent().(EQExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_5.getParent().(EQExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal)
}

from Function func, Variable vtype_260, Parameter vs_240
where
not func_0(vtype_260)
and not func_3(vtype_260, vs_240)
and func_4(vs_240)
and func_5(vs_240)
and vtype_260.getType().hasName("int")
and vs_240.getType().hasName("SSL *")
and vtype_260.getParentScope+() = func
and vs_240.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
