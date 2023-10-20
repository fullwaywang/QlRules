/**
 * @name php-cda7dcf4cacef3346f9dc2a4dc947e6a74769259-parse_ip_address_ex
 * @id cpp/php/cda7dcf4cacef3346f9dc2a4dc947e6a74769259/parse-ip-address-ex
 * @description php-cda7dcf4cacef3346f9dc2a4dc947e6a74769259-main/streams/xp_socket.c-parse_ip_address_ex CVE-2017-7189
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable ve_576, BlockStmt target_4, AddressOfExpr target_5, LogicalAndExpr target_2) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof LogicalAndExpr
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=ve_576
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="47"
		and target_0.getParent().(IfStmt).getThen()=target_4
		and target_5.getOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable ve_601, BlockStmt target_6, AddressOfExpr target_7, LogicalOrExpr target_3) {
	exists(LogicalOrExpr target_1 |
		target_1.getAnOperand() instanceof LogicalOrExpr
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=ve_601
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="47"
		and target_1.getParent().(IfStmt).getThen()=target_6
		and target_7.getOperand().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(NotExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable ve_576, BlockStmt target_4, LogicalAndExpr target_2) {
		target_2.getAnOperand().(VariableAccess).getTarget()=ve_576
		and target_2.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=ve_576
		and target_2.getParent().(IfStmt).getThen()=target_4
}

predicate func_3(Variable ve_601, BlockStmt target_6, LogicalOrExpr target_3) {
		target_3.getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=ve_601
		and target_3.getAnOperand().(NotExpr).getOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=ve_601
		and target_3.getParent().(IfStmt).getThen()=target_6
}

predicate func_4(BlockStmt target_4) {
		target_4.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("strpprintf")
		and target_4.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_4.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Failed to parse address \"%s\""
		and target_4.getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
}

predicate func_5(Variable ve_576, AddressOfExpr target_5) {
		target_5.getOperand().(VariableAccess).getTarget()=ve_576
}

predicate func_6(BlockStmt target_6) {
		target_6.getStmt(0).(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("_estrndup")
}

predicate func_7(Variable ve_601, AddressOfExpr target_7) {
		target_7.getOperand().(VariableAccess).getTarget()=ve_601
}

from Function func, Variable ve_576, Variable ve_601, LogicalAndExpr target_2, LogicalOrExpr target_3, BlockStmt target_4, AddressOfExpr target_5, BlockStmt target_6, AddressOfExpr target_7
where
not func_0(ve_576, target_4, target_5, target_2)
and not func_1(ve_601, target_6, target_7, target_3)
and func_2(ve_576, target_4, target_2)
and func_3(ve_601, target_6, target_3)
and func_4(target_4)
and func_5(ve_576, target_5)
and func_6(target_6)
and func_7(ve_601, target_7)
and ve_576.getType().hasName("char *")
and ve_601.getType().hasName("char *")
and ve_576.getParentScope+() = func
and ve_601.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
