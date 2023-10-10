/**
 * @name opensc-78cdab94-insert_key
 * @id cpp/opensc/78cdab94/insert-key
 * @description opensc-78cdab94-src/libopensc/pkcs15-tcos.c-insert_key CVE-2021-42782
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vi_128, BlockStmt target_2, ExprStmt target_3) {
	exists(AddExpr target_0 |
		target_0.getAnOperand().(VariableAccess).getTarget()=vi_128
		and target_0.getAnOperand().(Literal).getValue()="1"
		and target_0.getParent().(LTExpr).getLesserOperand().(VariableAccess).getTarget()=vi_128
		and target_0.getParent().(LTExpr).getParent().(ForStmt).getStmt()=target_2
		and target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vi_128, BlockStmt target_2, VariableAccess target_1) {
		target_1.getTarget()=vi_128
		and target_1.getParent().(LTExpr).getParent().(ForStmt).getStmt()=target_2
}

predicate func_2(Variable vi_128, BlockStmt target_2) {
		target_2.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_128
		and target_2.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(HexLiteral).getValue()="182"
		and target_2.getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_128
		and target_2.getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(HexLiteral).getValue()="184"
}

predicate func_3(Variable vi_128, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_128
		and target_3.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

from Function func, Variable vi_128, VariableAccess target_1, BlockStmt target_2, ExprStmt target_3
where
not func_0(vi_128, target_2, target_3)
and func_1(vi_128, target_2, target_1)
and func_2(vi_128, target_2)
and func_3(vi_128, target_3)
and vi_128.getType().hasName("int")
and vi_128.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
