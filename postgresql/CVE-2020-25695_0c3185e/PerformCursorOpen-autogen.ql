/**
 * @name postgresql-0c3185e963d9f9dd0608214f7d732b84aa0888fe-PerformCursorOpen
 * @id cpp/postgresql/0c3185e963d9f9dd0608214f7d732b84aa0888fe/PerformCursorOpen
 * @description postgresql-0c3185e963d9f9dd0608214f7d732b84aa0888fe-src/backend/commands/portalcmds.c-PerformCursorOpen CVE-2020-25695
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(NotExpr target_1, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(FunctionCall).getTarget().hasName("InSecurityRestrictedOperation")
		and target_0.getThen().(DoStmt).getCondition() instanceof Literal
		and target_0.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("errstart")
		and target_0.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(0) instanceof Literal
		and target_0.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(1) instanceof Literal
		and target_0.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(CommaExpr).getRightOperand().(FunctionCall).getTarget().hasName("errfinish")
		and target_0.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getValue()="1"
		and target_0.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__builtin_unreachable")
		and target_0.getParent().(IfStmt).getCondition()=target_1
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(NotExpr target_1) {
		target_1.getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="options"
		and target_1.getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("DeclareCursorStmt *")
		and target_1.getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="16"
        and target_1.getParent().(IfStmt).getThen().getAChild*().(FunctionCall).getTarget().hasName("RequireTransactionBlock")
}

from Function func, NotExpr target_1
where
not func_0(target_1, func)
and func_1(target_1)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
