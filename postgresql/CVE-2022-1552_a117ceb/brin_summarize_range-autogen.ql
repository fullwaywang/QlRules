/**
 * @name postgresql-a117cebd638dd02e5c2e791c25e43745f233111b-brin_summarize_range
 * @id cpp/postgresql/a117cebd638dd02e5c2e791c25e43745f233111b/brin-summarize-range
 * @description postgresql-a117cebd638dd02e5c2e791c25e43745f233111b-src/backend/access/brin/brin.c-brin_summarize_range CVE-2022-1552
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(EqualityOperation target_9, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("GetUserIdAndSecContext")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("Oid")
		and target_0.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vheapRel_1010, EqualityOperation target_9) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("SetUserIdAndSecContext")
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="relowner"
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rd_rel"
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vheapRel_1010
		and target_1.getExpr().(FunctionCall).getArgument(1).(BitwiseOrExpr).getLeftOperand().(VariableAccess).getType().hasName("int")
		and target_1.getExpr().(FunctionCall).getArgument(1).(BitwiseOrExpr).getRightOperand().(Literal).getValue()="2"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9)
}

predicate func_2(EqualityOperation target_9, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("NewGUCNestLevel")
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Variable vindexoid_1005, Variable vheapRel_1010, ExprStmt target_10, LogicalOrExpr target_11, ExprStmt target_12) {
	exists(LogicalAndExpr target_3 |
		target_3.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vheapRel_1010
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_3.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("pg_class_ownercheck")
		and target_3.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vindexoid_1005
		and target_3.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("Oid")
		and target_3.getParent().(IfStmt).getThen().(ExprStmt).getExpr() instanceof FunctionCall
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_3.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_11.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_12.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_5(Function func) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(FunctionCall).getTarget().hasName("AtEOXact_GUC")
		and target_5.getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_5.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("int")
		and (func.getEntryPoint().(BlockStmt).getStmt(20)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(20).getFollowingStmt()=target_5))
}

predicate func_6(Function func) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(FunctionCall).getTarget().hasName("SetUserIdAndSecContext")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("Oid")
		and target_6.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("int")
		and (func.getEntryPoint().(BlockStmt).getStmt(21)=target_6 or func.getEntryPoint().(BlockStmt).getStmt(21).getFollowingStmt()=target_6))
}

predicate func_7(Variable vheapoid_1008, Variable vheapRel_1010, EqualityOperation target_9, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vheapRel_1010
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("table_open")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vheapoid_1008
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="4"
		and target_7.getParent().(IfStmt).getCondition()=target_9
}

predicate func_8(Variable vindexoid_1005, FunctionCall target_8) {
		target_8.getTarget().hasName("GetUserId")
		and target_8.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("pg_class_ownercheck")
		and target_8.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vindexoid_1005
}

predicate func_9(Variable vheapoid_1008, EqualityOperation target_9) {
		target_9.getAnOperand().(VariableAccess).getTarget()=vheapoid_1008
		and target_9.getAnOperand().(Literal).getValue()="0"
}

predicate func_10(Variable vindexoid_1005, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("Relation")
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("index_open")
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vindexoid_1005
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="4"
}

predicate func_11(Variable vindexoid_1005, Variable vheapoid_1008, Variable vheapRel_1010, LogicalOrExpr target_11) {
		target_11.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vheapRel_1010
		and target_11.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_11.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vheapoid_1008
		and target_11.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("IndexGetRelation")
		and target_11.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vindexoid_1005
		and target_11.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(Literal).getValue()="0"
}

predicate func_12(Variable vheapRel_1010, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vheapRel_1010
		and target_12.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

from Function func, Variable vindexoid_1005, Variable vheapoid_1008, Variable vheapRel_1010, ExprStmt target_7, FunctionCall target_8, EqualityOperation target_9, ExprStmt target_10, LogicalOrExpr target_11, ExprStmt target_12
where
not func_0(target_9, func)
and not func_1(vheapRel_1010, target_9)
and not func_2(target_9, func)
and not func_3(vindexoid_1005, vheapRel_1010, target_10, target_11, target_12)
and not func_5(func)
and not func_6(func)
and func_7(vheapoid_1008, vheapRel_1010, target_9, target_7)
and func_8(vindexoid_1005, target_8)
and func_9(vheapoid_1008, target_9)
and func_10(vindexoid_1005, target_10)
and func_11(vindexoid_1005, vheapoid_1008, vheapRel_1010, target_11)
and func_12(vheapRel_1010, target_12)
and vindexoid_1005.getType().hasName("Oid")
and vheapoid_1008.getType().hasName("Oid")
and vheapRel_1010.getType().hasName("Relation")
and vindexoid_1005.(LocalVariable).getFunction() = func
and vheapoid_1008.(LocalVariable).getFunction() = func
and vheapRel_1010.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
