/**
 * @name sqlite3-0aa3231ff0af4873cee2b044d1ba2b55688152b9-sqlite3VListAdd
 * @id cpp/sqlite3/0aa3231ff0af4873cee2b044d1ba2b55688152b9/sqlite3VListAdd
 * @description sqlite3-0aa3231ff0af4873cee2b044d1ba2b55688152b9-src/util.c-sqlite3VListAdd CVE-2019-5827
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Parameter vpIn_1587, Variable vnInt_1592, LogicalOrExpr target_9, ExprStmt target_10) {
	exists(AddExpr target_1 |
		target_1.getAnOperand().(ConditionalExpr).getCondition().(VariableAccess).getTarget()=vpIn_1587
		and target_1.getAnOperand().(ConditionalExpr).getThen().(MulExpr).getLeftOperand() instanceof Literal
		and target_1.getAnOperand().(ConditionalExpr).getThen().(MulExpr).getRightOperand() instanceof ArrayExpr
		and target_1.getAnOperand().(ConditionalExpr).getElse() instanceof Literal
		and target_1.getAnOperand().(VariableAccess).getTarget()=vnInt_1592
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(ConditionalExpr).getCondition().(VariableAccess).getLocation())
		and target_1.getAnOperand().(VariableAccess).getLocation().isBefore(target_10.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vpIn_1587, ArrayExpr target_2) {
		target_2.getArrayBase().(VariableAccess).getTarget()=vpIn_1587
		and target_2.getArrayOffset().(Literal).getValue()="0"
}

predicate func_3(Parameter vpIn_1587, VariableAccess target_3) {
		target_3.getTarget()=vpIn_1587
}

predicate func_5(Variable vnInt_1592, VariableAccess target_5) {
		target_5.getTarget()=vnInt_1592
}

predicate func_8(Parameter vpIn_1587, Variable vnInt_1592, AddExpr target_8) {
		target_8.getAnOperand().(ConditionalExpr).getCondition().(VariableAccess).getTarget()=vpIn_1587
		and target_8.getAnOperand().(ConditionalExpr).getThen().(MulExpr).getLeftOperand() instanceof ArrayExpr
		and target_8.getAnOperand().(ConditionalExpr).getThen().(MulExpr).getRightOperand() instanceof Literal
		and target_8.getAnOperand().(ConditionalExpr).getElse() instanceof Literal
		and target_8.getAnOperand().(VariableAccess).getTarget()=vnInt_1592
}

predicate func_9(Parameter vpIn_1587, Variable vnInt_1592, LogicalOrExpr target_9) {
		target_9.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vpIn_1587
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_9.getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpIn_1587
		and target_9.getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_9.getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vnInt_1592
		and target_9.getAnOperand().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpIn_1587
		and target_9.getAnOperand().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

predicate func_10(Parameter vpIn_1587, Variable vnInt_1592, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpIn_1587
		and target_10.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_10.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_10.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vnInt_1592
}

from Function func, Parameter vpIn_1587, Variable vnInt_1592, ArrayExpr target_2, VariableAccess target_3, VariableAccess target_5, AddExpr target_8, LogicalOrExpr target_9, ExprStmt target_10
where
not func_1(vpIn_1587, vnInt_1592, target_9, target_10)
and func_2(vpIn_1587, target_2)
and func_3(vpIn_1587, target_3)
and func_5(vnInt_1592, target_5)
and func_8(vpIn_1587, vnInt_1592, target_8)
and func_9(vpIn_1587, vnInt_1592, target_9)
and func_10(vpIn_1587, vnInt_1592, target_10)
and vpIn_1587.getType().hasName("VList *")
and vnInt_1592.getType().hasName("int")
and vpIn_1587.getFunction() = func
and vnInt_1592.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
