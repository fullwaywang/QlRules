/**
 * @name postgresql-5579726bd60a6e7afb04a3548bced348cd5ffd89-recordDependencyOnCurrentExtension
 * @id cpp/postgresql/5579726bd60a6e7afb04a3548bced348cd5ffd89/recordDependencyOnCurrentExtension
 * @description postgresql-5579726bd60a6e7afb04a3548bced348cd5ffd89-src/backend/catalog/pg_depend.c-recordDependencyOnCurrentExtension CVE-2022-2625
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable v__func__, VariableAccess target_1, FunctionCall target_2) {
	exists(DoStmt target_0 |
		target_0.getCondition() instanceof Literal
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("errstart")
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(0) instanceof Literal
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(2) instanceof Literal
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=v__func__
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(4) instanceof Literal
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(FunctionCall).getTarget().hasName("errdetail")
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(CommaExpr).getRightOperand().(FunctionCall).getTarget().hasName("errfinish")
		and target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(CommaExpr).getRightOperand().(FunctionCall).getArgument(0) instanceof Literal
		and target_0.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getValue()="1"
		and target_0.getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__builtin_unreachable")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getArgument(3).(VariableAccess).getLocation().isBefore(target_0.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(3).(VariableAccess).getLocation()))
}

predicate func_1(Parameter visReplace_139, VariableAccess target_1) {
		target_1.getTarget()=visReplace_139
}

predicate func_2(Variable v__func__, FunctionCall target_2) {
		target_2.getTarget().hasName("errstart")
		and target_2.getArgument(0) instanceof Literal
		and target_2.getArgument(1) instanceof StringLiteral
		and target_2.getArgument(2) instanceof Literal
		and target_2.getArgument(3).(VariableAccess).getTarget()=v__func__
		and target_2.getArgument(4) instanceof Literal
}

from Function func, Parameter visReplace_139, Variable v__func__, VariableAccess target_1, FunctionCall target_2
where
not func_0(v__func__, target_1, target_2)
and func_1(visReplace_139, target_1)
and func_2(v__func__, target_2)
and visReplace_139.getType().hasName("bool")
and v__func__.getType() instanceof ArrayType
and visReplace_139.getFunction() = func
and not v__func__.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
