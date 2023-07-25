/**
 * @name sqlite3-0aa3231ff0af4873cee2b044d1ba2b55688152b9-sqlite3VdbeSorterWrite
 * @id cpp/sqlite3/0aa3231ff0af4873cee2b044d1ba2b55688152b9/sqlite3VdbeSorterWrite
 * @description sqlite3-0aa3231ff0af4873cee2b044d1ba2b55688152b9-src/vdbesort.c-sqlite3VdbeSorterWrite CVE-2019-5827
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vpSorter_1765, PointerArithmeticOperation target_6, RelationalOperation target_7) {
	exists(MulExpr target_1 |
		target_1.getLeftOperand() instanceof Literal
		and target_1.getRightOperand().(PointerFieldAccess).getTarget().getName()="nMemory"
		and target_1.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpSorter_1765
		and target_6.getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vpSorter_1765, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="nMemory"
		and target_2.getQualifier().(VariableAccess).getTarget()=vpSorter_1765
}

predicate func_5(Variable vpSorter_1765, MulExpr target_5) {
		target_5.getLeftOperand().(PointerFieldAccess).getTarget().getName()="nMemory"
		and target_5.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpSorter_1765
		and target_5.getRightOperand() instanceof Literal
}

predicate func_6(Variable vpSorter_1765, PointerArithmeticOperation target_6) {
		target_6.getLeftOperand().(ValueFieldAccess).getTarget().getName()="pList"
		and target_6.getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="list"
		and target_6.getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpSorter_1765
		and target_6.getRightOperand().(ValueFieldAccess).getTarget().getName()="aMemory"
		and target_6.getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="list"
		and target_6.getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpSorter_1765
}

predicate func_7(Variable vpSorter_1765, RelationalOperation target_7) {
		 (target_7 instanceof GTExpr or target_7 instanceof LTExpr)
		and target_7.getGreaterOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_7.getLesserOperand().(PointerFieldAccess).getTarget().getName()="mxPmaSize"
		and target_7.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpSorter_1765
}

from Function func, Variable vpSorter_1765, PointerFieldAccess target_2, MulExpr target_5, PointerArithmeticOperation target_6, RelationalOperation target_7
where
not func_1(vpSorter_1765, target_6, target_7)
and func_2(vpSorter_1765, target_2)
and func_5(vpSorter_1765, target_5)
and func_6(vpSorter_1765, target_6)
and func_7(vpSorter_1765, target_7)
and vpSorter_1765.getType().hasName("VdbeSorter *")
and vpSorter_1765.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
