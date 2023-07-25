/**
 * @name postgresql-f02b9085ad2f6fefd9c5cdf85579cb9f0ff0f0ea-makeArrayResultArr
 * @id cpp/postgresql/f02b9085ad2f6fefd9c5cdf85579cb9f0ff0f0ea/makeArrayResultArr
 * @description postgresql-f02b9085ad2f6fefd9c5cdf85579cb9f0ff0f0ea-src/backend/utils/adt/arrayfuncs.c-makeArrayResultArr CVE-2021-32027
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vastate_5432, EqualityOperation target_2, ExprStmt target_3) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("ArrayGetNItems")
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ndims"
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vastate_5432
		and target_0.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="dims"
		and target_0.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vastate_5432
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vastate_5432, EqualityOperation target_2, ExprStmt target_4) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("ArrayCheckBounds")
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ndims"
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vastate_5432
		and target_1.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="dims"
		and target_1.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vastate_5432
		and target_1.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="lbs"
		and target_1.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vastate_5432
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(2)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vastate_5432, EqualityOperation target_2) {
		target_2.getAnOperand().(PointerFieldAccess).getTarget().getName()="ndims"
		and target_2.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vastate_5432
		and target_2.getAnOperand().(Literal).getValue()="0"
}

predicate func_3(Parameter vastate_5432, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("ArrayType *")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("construct_empty_array")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="element_type"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vastate_5432
}

predicate func_4(Parameter vastate_5432, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_4.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="nbytes"
		and target_4.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vastate_5432
}

from Function func, Parameter vastate_5432, EqualityOperation target_2, ExprStmt target_3, ExprStmt target_4
where
not func_0(vastate_5432, target_2, target_3)
and not func_1(vastate_5432, target_2, target_4)
and func_2(vastate_5432, target_2)
and func_3(vastate_5432, target_3)
and func_4(vastate_5432, target_4)
and vastate_5432.getType().hasName("ArrayBuildStateArr *")
and vastate_5432.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
