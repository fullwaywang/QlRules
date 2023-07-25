/**
 * @name openssl-1dd43e0709fece299b15208f36cc7c76209ba0bb-check_policy
 * @id cpp/openssl/1dd43e0709fece299b15208f36cc7c76209ba0bb/check-policy
 * @description openssl-1dd43e0709fece299b15208f36cc7c76209ba0bb-crypto/x509/x509_vfy.c-check_policy CVE-2023-0465
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="1"
		and not target_0.getValue()="0"
		and target_0.getEnclosingFunction() = func
}

predicate func_2(Variable vx_1661, LogicalAndExpr target_4) {
	exists(IfStmt target_2 |
		target_2.getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="ex_flags"
		and target_2.getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vx_1661
		and target_2.getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="2048"
		and target_2.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_2.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_2.getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(EqualityOperation target_5, Function func) {
	exists(IfStmt target_3 |
		target_3.getCondition().(NotExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(FunctionCall).getTarget().hasName("ERR_new")
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(FunctionCall).getTarget().hasName("ERR_set_debug")
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(0).(Literal).getValue()="11"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(1).(BitwiseOrExpr).getValue()="786691"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(ExprCall).getArgument(2).(Literal).getValue()="0"
		and target_3.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Variable vx_1661, LogicalAndExpr target_4) {
		target_4.getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="ex_flags"
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vx_1661
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="2048"
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("verify_cb_cert")
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vx_1661
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(3).(Literal).getValue()="42"
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

predicate func_5(EqualityOperation target_5) {
		target_5.getAnOperand().(UnaryMinusExpr).getValue()="-1"
}

from Function func, Variable vx_1661, Literal target_0, LogicalAndExpr target_4, EqualityOperation target_5
where
func_0(func, target_0)
and not func_2(vx_1661, target_4)
and not func_3(target_5, func)
and func_4(vx_1661, target_4)
and func_5(target_5)
and vx_1661.getType().hasName("X509 *")
and vx_1661.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
