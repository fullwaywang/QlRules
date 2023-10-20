/**
 * @name sqlite3-a6c1a71cde082e09750465d5675699062922e387-selectExpander
 * @id cpp/sqlite3/a6c1a71cde082e09750465d5675699062922e387/selectExpander
 * @description sqlite3-a6c1a71cde082e09750465d5675699062922e387-src/select.c-selectExpander CVE-2019-20218
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vpParse_4884, Variable vdb_4889, BlockStmt target_2, FunctionCall target_3, LogicalOrExpr target_4, ExprStmt target_5, IfStmt target_6) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(PointerFieldAccess).getTarget().getName()="nErr"
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpParse_4884
		and target_0.getAnOperand().(PointerFieldAccess).getTarget().getName()="mallocFailed"
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdb_4889
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="mallocFailed"
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdb_4889
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("sqliteProcessJoin")
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpParse_4884
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("Select *")
		and target_0.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_2
		and target_3.getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vpParse_4884, Variable vdb_4889, BlockStmt target_2, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="mallocFailed"
		and target_1.getQualifier().(VariableAccess).getTarget()=vdb_4889
		and target_1.getParent().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("sqliteProcessJoin")
		and target_1.getParent().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpParse_4884
		and target_1.getParent().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("Select *")
		and target_1.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_2
}

predicate func_2(BlockStmt target_2) {
		target_2.getStmt(0).(ReturnStmt).getExpr().(Literal).getValue()="2"
}

predicate func_3(Variable vpParse_4884, FunctionCall target_3) {
		target_3.getTarget().hasName("sqlite3IndexedByLookup")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vpParse_4884
		and target_3.getArgument(1).(VariableAccess).getTarget().getType().hasName("SrcList_item *")
}

predicate func_4(Variable vpParse_4884, Variable vdb_4889, LogicalOrExpr target_4) {
		target_4.getAnOperand().(PointerFieldAccess).getTarget().getName()="mallocFailed"
		and target_4.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdb_4889
		and target_4.getAnOperand().(FunctionCall).getTarget().hasName("sqliteProcessJoin")
		and target_4.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpParse_4884
		and target_4.getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("Select *")
}

predicate func_5(Variable vdb_4889, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="pSelect"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("SrcList_item *")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("sqlite3SelectDup")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdb_4889
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="pSelect"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("Table *")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0"
}

predicate func_6(Variable vdb_4889, IfStmt target_6) {
		target_6.getCondition().(PointerFieldAccess).getTarget().getName()="mallocFailed"
		and target_6.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdb_4889
}

from Function func, Variable vpParse_4884, Variable vdb_4889, PointerFieldAccess target_1, BlockStmt target_2, FunctionCall target_3, LogicalOrExpr target_4, ExprStmt target_5, IfStmt target_6
where
not func_0(vpParse_4884, vdb_4889, target_2, target_3, target_4, target_5, target_6)
and func_1(vpParse_4884, vdb_4889, target_2, target_1)
and func_2(target_2)
and func_3(vpParse_4884, target_3)
and func_4(vpParse_4884, vdb_4889, target_4)
and func_5(vdb_4889, target_5)
and func_6(vdb_4889, target_6)
and vpParse_4884.getType().hasName("Parse *")
and vdb_4889.getType().hasName("sqlite3 *")
and vpParse_4884.(LocalVariable).getFunction() = func
and vdb_4889.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
