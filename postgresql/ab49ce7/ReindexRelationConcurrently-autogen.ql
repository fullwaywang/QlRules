/**
 * @name postgresql-ab49ce7c3414ac19e4afb386d7843ce2d2fb8bda-ReindexRelationConcurrently
 * @id cpp/postgresql/ab49ce7c3414ac19e4afb386d7843ce2d2fb8bda/ReindexRelationConcurrently
 * @description postgresql-ab49ce7c3414ac19e4afb386d7843ce2d2fb8bda-src/backend/commands/indexcmds.c-ReindexRelationConcurrently CVE-2022-1552
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("GetUserIdAndSecContext")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("Oid")
		and target_0.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vheapRel_3538, ExprStmt target_5, ExprStmt target_6) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("SetUserIdAndSecContext")
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="relowner"
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rd_rel"
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vheapRel_3538
		and target_1.getExpr().(FunctionCall).getArgument(1).(BitwiseOrExpr).getLeftOperand().(VariableAccess).getType().hasName("int")
		and target_1.getExpr().(FunctionCall).getArgument(1).(BitwiseOrExpr).getRightOperand().(Literal).getValue()="2"
		and target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("NewGUCNestLevel")
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(FunctionCall).getTarget().hasName("AtEOXact_GUC")
		and target_3.getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_3.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("int")
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(FunctionCall).getTarget().hasName("SetUserIdAndSecContext")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("Oid")
		and target_4.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("int")
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Variable vheapRel_3538, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vheapRel_3538
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("table_open")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="indrelid"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rd_index"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("Relation")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="4"
}

predicate func_6(Variable vheapRel_3538, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="tableId"
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("ReindexIndexInfo *")
		and target_6.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="rd_id"
		and target_6.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vheapRel_3538
}

from Function func, Variable vheapRel_3538, ExprStmt target_5, ExprStmt target_6
where
not func_0(func)
and not func_1(vheapRel_3538, target_5, target_6)
and not func_2(func)
and not func_3(func)
and not func_4(func)
and func_5(vheapRel_3538, target_5)
and func_6(vheapRel_3538, target_6)
and vheapRel_3538.getType().hasName("Relation")
and vheapRel_3538.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
