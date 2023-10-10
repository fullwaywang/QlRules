/**
 * @name postgresql-28e24125541545483093819efae9bca603441951-ProcessStartupPacket
 * @id cpp/postgresql/28e24125541545483093819efae9bca603441951/ProcessStartupPacket
 * @description postgresql-28e24125541545483093819efae9bca603441951-src/backend/postmaster/postmaster.c-ProcessStartupPacket CVE-2021-23214
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(LogicalAndExpr target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(FunctionCall).getTarget().hasName("pq_buffer_has_data")
		and target_0.getThen().(DoStmt).getCondition() instanceof Literal
		and target_0.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(ConditionalExpr).getCondition().(LogicalAndExpr).getValue()="1"
		and target_0.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(ConditionalExpr).getThen().(FunctionCall).getTarget().hasName("errstart_cold")
		and target_0.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(ConditionalExpr).getThen().(FunctionCall).getArgument(0).(Literal).getValue()="22"
		and target_0.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(ConditionalExpr).getThen().(FunctionCall).getArgument(1) instanceof Literal
		and target_0.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(ConditionalExpr).getElse().(FunctionCall).getTarget().hasName("errstart")
		and target_0.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(Literal).getValue()="22"
		and target_0.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(ConditionalExpr).getElse().(FunctionCall).getArgument(1) instanceof Literal
		and target_0.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(CommaExpr).getRightOperand().(FunctionCall).getTarget().hasName("errfinish")
		and target_0.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getValue()="1"
		and target_0.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__builtin_unreachable")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_0.getEnclosingFunction() = func)
}

predicate func_2(LogicalAndExpr target_2) {
		target_2.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("ProtocolVersion")
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(BitwiseOrExpr).getValue()="80877103"
		and target_2.getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget().getType().hasName("bool")
}

predicate func_3(LogicalAndExpr target_3) {
		target_3.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("ProtocolVersion")
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(BitwiseOrExpr).getValue()="80877104"
		and target_3.getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget().getType().hasName("bool")
}

predicate func_4(LogicalAndExpr target_2, ReturnStmt target_4, Function func) {
        target_4.getExpr().(FunctionCall).getTarget()=func
        and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
}

predicate func_5(LogicalAndExpr target_3, ReturnStmt target_5, Function func) {
        target_5.getExpr().(FunctionCall).getTarget()=func
        and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
}

from Function func, LogicalAndExpr target_2, LogicalAndExpr target_3, ReturnStmt target_4, ReturnStmt target_5
where
not func_0(target_2, func)
and not func_0(target_3, func)
and func_2(target_2)
and func_3(target_3)
and func_4(target_2, target_4, func)
and func_5(target_3, target_5, func)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
