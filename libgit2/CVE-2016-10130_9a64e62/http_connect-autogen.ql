/**
 * @name libgit2-9a64e62f0f20c9cf9b2e1609f037060eb2d8eb22-http_connect
 * @id cpp/libgit2/9a64e62f0f20c9cf9b2e1609f037060eb2d8eb22/http-connect
 * @description libgit2-9a64e62f0f20c9cf9b2e1609f037060eb2d8eb22-src/transports/http.c-http_connect CVE-2016-10130
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable verror_591, ReturnStmt target_4) {
	exists(Initializer target_1 |
		target_1.getExpr().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=verror_591
		and target_4.getExpr().(VariableAccess).getLocation().isBefore(target_1.getExpr().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable verror_591, VariableAccess target_2) {
		target_2.getTarget()=verror_591
}

predicate func_3(Variable verror_591, Variable vis_valid_627, LogicalAndExpr target_5, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vis_valid_627
		and target_3.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=verror_591
		and target_3.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand() instanceof EnumConstantAccess
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
}

predicate func_4(Variable verror_591, ReturnStmt target_4) {
		target_4.getExpr().(VariableAccess).getTarget()=verror_591
}

predicate func_5(Variable verror_591, LogicalAndExpr target_5) {
		target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=verror_591
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=verror_591
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="certificate_check_cb"
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="owner"
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_5.getAnOperand().(FunctionCall).getTarget().hasName("git_stream_is_encrypted")
		and target_5.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="io"
}

from Function func, Variable verror_591, Variable vis_valid_627, VariableAccess target_2, ExprStmt target_3, ReturnStmt target_4, LogicalAndExpr target_5
where
not func_1(verror_591, target_4)
and func_2(verror_591, target_2)
and func_3(verror_591, vis_valid_627, target_5, target_3)
and func_4(verror_591, target_4)
and func_5(verror_591, target_5)
and verror_591.getType().hasName("int")
and vis_valid_627.getType().hasName("int")
and verror_591.getParentScope+() = func
and vis_valid_627.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
