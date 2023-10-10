/**
 * @name postgresql-87b2ebd-transformOnConflictArbiter
 * @id cpp/postgresql/87b2ebd/transformOnConflictArbiter
 * @description postgresql-87b2ebd-src/backend/parser/parse_clause.c-transformOnConflictArbiter CVE-2017-15099
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vconstraint_3103, Variable vinfer_3105, ExprStmt target_8, IfStmt target_9) {
	exists(AssignExpr target_0 |
		target_0.getLValue().(VariableAccess).getType().hasName("Bitmapset *")
		and target_0.getRValue().(FunctionCall).getTarget().hasName("get_relation_constraint_attnos")
		and target_0.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("Oid")
		and target_0.getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="conname"
		and target_0.getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinfer_3105
		and target_0.getRValue().(FunctionCall).getArgument(2) instanceof Literal
		and target_0.getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vconstraint_3103
		and target_8.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_0.getRValue().(FunctionCall).getArgument(3).(VariableAccess).getLocation())
		and target_9.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(PointerFieldAccess target_10, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="requiredPerms"
		and target_1.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("RangeTblEntry *")
		and target_1.getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getValue()="2"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(4)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(PointerFieldAccess target_10, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="selectedCols"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("RangeTblEntry *")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("bms_add_members")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="selectedCols"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("RangeTblEntry *")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("Bitmapset *")
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(5)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Variable vinfer_3105, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="conname"
		and target_3.getQualifier().(VariableAccess).getTarget()=vinfer_3105
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_4(Parameter vpstate_3100, PointerFieldAccess target_4) {
		target_4.getTarget().getName()="rd_id"
		and target_4.getQualifier().(PointerFieldAccess).getTarget().getName()="p_target_relation"
		and target_4.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpstate_3100
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_6(Parameter vconstraint_3103, VariableAccess target_6) {
		target_6.getTarget()=vconstraint_3103
}

predicate func_7(Parameter vpstate_3100, Parameter vconstraint_3103, Variable vinfer_3105, AssignExpr target_7) {
		target_7.getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vconstraint_3103
		and target_7.getRValue().(FunctionCall).getTarget().hasName("get_relation_constraint_oid")
		and target_7.getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="rd_id"
		and target_7.getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="p_target_relation"
		and target_7.getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpstate_3100
		and target_7.getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="conname"
		and target_7.getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinfer_3105
		and target_7.getRValue().(FunctionCall).getArgument(2) instanceof Literal
}

predicate func_8(Parameter vconstraint_3103, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vconstraint_3103
		and target_8.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_9(Variable vinfer_3105, IfStmt target_9) {
		target_9.getCondition().(PointerFieldAccess).getTarget().getName()="conname"
		and target_9.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinfer_3105
		and target_9.getThen().(ExprStmt).getExpr() instanceof AssignExpr
}

predicate func_10(Variable vinfer_3105, PointerFieldAccess target_10) {
		target_10.getTarget().getName()="conname"
		and target_10.getQualifier().(VariableAccess).getTarget()=vinfer_3105
}

from Function func, Parameter vpstate_3100, Parameter vconstraint_3103, Variable vinfer_3105, PointerFieldAccess target_3, PointerFieldAccess target_4, VariableAccess target_6, AssignExpr target_7, ExprStmt target_8, IfStmt target_9, PointerFieldAccess target_10
where
not func_0(vconstraint_3103, vinfer_3105, target_8, target_9)
and not func_1(target_10, func)
and not func_2(target_10, func)
and func_3(vinfer_3105, target_3)
and func_4(vpstate_3100, target_4)
and func_6(vconstraint_3103, target_6)
and func_7(vpstate_3100, vconstraint_3103, vinfer_3105, target_7)
and func_8(vconstraint_3103, target_8)
and func_9(vinfer_3105, target_9)
and func_10(vinfer_3105, target_10)
and vpstate_3100.getType().hasName("ParseState *")
and vconstraint_3103.getType().hasName("Oid *")
and vinfer_3105.getType().hasName("InferClause *")
and vpstate_3100.getFunction() = func
and vconstraint_3103.getFunction() = func
and vinfer_3105.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
