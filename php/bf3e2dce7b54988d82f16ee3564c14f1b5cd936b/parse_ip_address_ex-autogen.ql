/**
 * @name php-bf3e2dce7b54988d82f16ee3564c14f1b5cd936b-parse_ip_address_ex
 * @id cpp/php/bf3e2dce7b54988d82f16ee3564c14f1b5cd936b/parse-ip-address-ex
 * @description php-bf3e2dce7b54988d82f16ee3564c14f1b5cd936b-main/streams/xp_socket.c-parse_ip_address_ex CVE-2017-7189
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable ve_576, BlockStmt target_4, LogicalAndExpr target_0) {
		target_0.getAnOperand().(VariableAccess).getTarget()=ve_576
		and target_0.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=ve_576
		and target_0.getParent().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_4
}

predicate func_1(Variable ve_601, BlockStmt target_5, LogicalOrExpr target_1) {
		target_1.getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=ve_601
		and target_1.getAnOperand().(NotExpr).getOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=ve_601
		and target_1.getParent().(LogicalOrExpr).getAnOperand() instanceof EqualityOperation
		and target_1.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_5
}

predicate func_2(Variable ve_576, BlockStmt target_4, LogicalAndExpr target_2) {
		target_2.getAnOperand() instanceof LogicalAndExpr
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=ve_576
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="47"
		and target_2.getParent().(IfStmt).getThen()=target_4
}

predicate func_3(Variable ve_601, BlockStmt target_5, LogicalOrExpr target_3) {
		target_3.getAnOperand() instanceof LogicalOrExpr
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=ve_601
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="47"
		and target_3.getParent().(IfStmt).getThen()=target_5
}

predicate func_4(BlockStmt target_4) {
		target_4.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("strpprintf")
		and target_4.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_4.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Failed to parse address \"%s\""
		and target_4.getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
}

predicate func_5(BlockStmt target_5) {
		target_5.getStmt(0).(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("_estrndup")
}

from Function func, Variable ve_576, Variable ve_601, LogicalAndExpr target_0, LogicalOrExpr target_1, LogicalAndExpr target_2, LogicalOrExpr target_3, BlockStmt target_4, BlockStmt target_5
where
func_0(ve_576, target_4, target_0)
and func_1(ve_601, target_5, target_1)
and func_2(ve_576, target_4, target_2)
and func_3(ve_601, target_5, target_3)
and func_4(target_4)
and func_5(target_5)
and ve_576.getType().hasName("char *")
and ve_601.getType().hasName("char *")
and ve_576.getParentScope+() = func
and ve_601.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
