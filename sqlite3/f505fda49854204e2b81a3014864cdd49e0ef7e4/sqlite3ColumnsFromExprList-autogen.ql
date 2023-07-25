/**
 * @name sqlite3-f505fda49854204e2b81a3014864cdd49e0ef7e4-sqlite3ColumnsFromExprList
 * @id cpp/sqlite3/f505fda49854204e2b81a3014864cdd49e0ef7e4/sqlite3ColumnsFromExprList
 * @description sqlite3-f505fda49854204e2b81a3014864cdd49e0ef7e4-src/select.c-sqlite3ColumnsFromExprList CVE-2020-13871
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(EqualityOperation target_1, Function func, ExprStmt target_0) {
		target_0.getExpr().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_0.getEnclosingFunction() = func
}

predicate func_1(EqualityOperation target_1) {
		target_1.getAnOperand().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("char *")
		and target_1.getAnOperand().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="zName"
		and target_1.getAnOperand().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="a"
		and target_1.getAnOperand().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("ExprList *")
		and target_1.getAnOperand().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
		and target_1.getAnOperand().(Literal).getValue()="0"
}

from Function func, ExprStmt target_0, EqualityOperation target_1
where
func_0(target_1, func, target_0)
and func_1(target_1)
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
