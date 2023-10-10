/**
 * @name postgresql-b8a1247a34e234be6becf7f70b9f1e8e9369db64-fireRIRrules
 * @id cpp/postgresql/b8a1247a34e234be6becf7f70b9f1e8e9369db64/fireRIRrules
 * @description postgresql-b8a1247a34e234be6becf7f70b9f1e8e9369db64-src/backend/rewrite/rewriteHandler.c-fireRIRrules CVE-2018-10925
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vrt_index_1722, Parameter vparsetree_1719, SubExpr target_1, LogicalAndExpr target_2, ExprStmt target_3) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="onConflict"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparsetree_1719
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vrt_index_1722
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="exclRelIndex"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="onConflict"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparsetree_1719
		and target_1.getLeftOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vrt_index_1722, SubExpr target_1) {
		target_1.getLeftOperand().(VariableAccess).getTarget()=vrt_index_1722
		and target_1.getRightOperand().(Literal).getValue()="1"
}

predicate func_2(Variable vrt_index_1722, Parameter vparsetree_1719, LogicalAndExpr target_2) {
		target_2.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vrt_index_1722
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="resultRelation"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparsetree_1719
		and target_2.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("rangeTableEntry_used")
		and target_2.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vparsetree_1719
		and target_2.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vrt_index_1722
		and target_2.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(Literal).getValue()="0"
}

predicate func_3(Variable vrt_index_1722, Parameter vparsetree_1719, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("RangeTblEntry *")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("list_nth")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="rtable"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparsetree_1719
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vrt_index_1722
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(SubExpr).getRightOperand().(Literal).getValue()="1"
}

from Function func, Variable vrt_index_1722, Parameter vparsetree_1719, SubExpr target_1, LogicalAndExpr target_2, ExprStmt target_3
where
not func_0(vrt_index_1722, vparsetree_1719, target_1, target_2, target_3)
and func_1(vrt_index_1722, target_1)
and func_2(vrt_index_1722, vparsetree_1719, target_2)
and func_3(vrt_index_1722, vparsetree_1719, target_3)
and vrt_index_1722.getType().hasName("int")
and vparsetree_1719.getType().hasName("Query *")
and vrt_index_1722.(LocalVariable).getFunction() = func
and vparsetree_1719.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
