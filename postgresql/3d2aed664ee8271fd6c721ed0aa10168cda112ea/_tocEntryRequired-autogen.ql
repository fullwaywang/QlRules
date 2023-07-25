/**
 * @name postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-_tocEntryRequired
 * @id cpp/postgresql/3d2aed664ee8271fd6c721ed0aa10168cda112ea/-tocEntryRequired
 * @description postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-src/bin/pg_dump/pg_backup_archiver.c-_tocEntryRequired CVE-2018-1058
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vte_2812, LogicalOrExpr target_1) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof LogicalOrExpr
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="desc"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vte_2812
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="SEARCHPATH"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getParent().(IfStmt).getThen().(ReturnStmt).getExpr() instanceof EnumConstantAccess
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vte_2812, LogicalOrExpr target_1) {
		target_1.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="desc"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vte_2812
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="ENCODING"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="desc"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vte_2812
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="STDSTRINGS"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen().(ReturnStmt).getExpr() instanceof EnumConstantAccess
}

from Function func, Parameter vte_2812, LogicalOrExpr target_1
where
not func_0(vte_2812, target_1)
and func_1(vte_2812, target_1)
and vte_2812.getType().hasName("TocEntry *")
and vte_2812.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
