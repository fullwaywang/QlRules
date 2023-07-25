/**
 * @name sqlite3-23ee89375284ba23b42d81c4ce3a39d656b0996d-unixTempFileDir
 * @id cpp/sqlite3/23ee89375284ba23b42d81c4ce3a39d656b0996d/unixTempFileDir
 * @description sqlite3-23ee89375284ba23b42d81c4ce3a39d656b0996d-src/os_unix.c-unixTempFileDir CVE-2016-6153
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vi_5413, BlockStmt target_4, ExprStmt target_5) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GEExpr or target_0 instanceof LEExpr)
		and target_0.getLesserOperand().(VariableAccess).getTarget()=vi_5413
		and target_0.getGreaterOperand() instanceof DivExpr
		and target_0.getParent().(ForStmt).getStmt()=target_4
		and target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vi_5413, BlockStmt target_4, DivExpr target_1) {
		target_1.getValue()="6"
		and target_1.getParent().(LTExpr).getLesserOperand().(VariableAccess).getTarget()=vi_5413
		and target_1.getParent().(LTExpr).getParent().(ForStmt).getStmt()=target_4
}

/*predicate func_2(Variable vi_5413, BlockStmt target_4, VariableAccess target_2) {
		target_2.getTarget()=vi_5413
		and target_2.getParent().(LTExpr).getGreaterOperand().(DivExpr).getValue()="6"
		and target_2.getParent().(LTExpr).getParent().(ForStmt).getStmt()=target_4
}

*/
predicate func_3(Variable vi_5413, BlockStmt target_4, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getLesserOperand().(VariableAccess).getTarget()=vi_5413
		and target_3.getGreaterOperand() instanceof DivExpr
		and target_3.getParent().(ForStmt).getStmt()=target_4
}

predicate func_4(BlockStmt target_4) {
		target_4.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("const char *")
		and target_4.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_4.getStmt(1).(IfStmt).getCondition().(VariableCall).getExpr().(ValueFieldAccess).getTarget().getName()="pCurrent"
		and target_4.getStmt(1).(IfStmt).getCondition().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType() instanceof ArrayType
		and target_4.getStmt(1).(IfStmt).getCondition().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="4"
		and target_4.getStmt(1).(IfStmt).getCondition().(VariableCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("const char *")
		and target_4.getStmt(1).(IfStmt).getCondition().(VariableCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("stat")
}

predicate func_5(Variable vi_5413, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_5413
		and target_5.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

from Function func, Variable vi_5413, DivExpr target_1, RelationalOperation target_3, BlockStmt target_4, ExprStmt target_5
where
not func_0(vi_5413, target_4, target_5)
and func_1(vi_5413, target_4, target_1)
and func_3(vi_5413, target_4, target_3)
and func_4(target_4)
and func_5(vi_5413, target_5)
and vi_5413.getType().hasName("unsigned int")
and vi_5413.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
