/**
 * @name postgresql-3bb3f42f3749d40b8d4de65871e8d828b18d4a45-dovec
 * @id cpp/postgresql/3bb3f42f3749d40b8d4de65871e8d828b18d4a45/dovec
 * @description postgresql-3bb3f42f3749d40b8d4de65871e8d828b18d4a45-src/backend/regex/regcomp.c-dovec CVE-2016-0773
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vv_1580, FunctionCall target_4, ExprStmt target_5) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="err"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vv_1580
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_4.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Parameter vv_1580, ExprStmt target_5) {
	exists(IfStmt target_2 |
		target_2.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="err"
		and target_2.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vv_1580
		and target_2.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_4(Parameter vv_1580, FunctionCall target_4) {
		target_4.getTarget().hasName("subcolor")
		and target_4.getArgument(0).(PointerFieldAccess).getTarget().getName()="cm"
		and target_4.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vv_1580
		and target_4.getArgument(1).(VariableAccess).getTarget().getType().hasName("chr")
}

predicate func_5(Parameter vv_1580, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("subrange")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vv_1580
		and target_5.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("chr")
		and target_5.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("chr")
		and target_5.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("state *")
		and target_5.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget().getType().hasName("state *")
}

from Function func, Parameter vv_1580, FunctionCall target_4, ExprStmt target_5
where
not func_0(vv_1580, target_4, target_5)
and not func_2(vv_1580, target_5)
and func_4(vv_1580, target_4)
and func_5(vv_1580, target_5)
and vv_1580.getType().hasName("vars *")
and vv_1580.getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
