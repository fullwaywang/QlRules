/**
 * @name postgresql-ab49ce7c3414ac19e4afb386d7843ce2d2fb8bda-brin_summarize_range
 * @id cpp/postgresql/ab49ce7c3414ac19e4afb386d7843ce2d2fb8bda/brin-summarize-range
 * @description postgresql-ab49ce7c3414ac19e4afb386d7843ce2d2fb8bda-src/backend/access/brin/brin.c-brin_summarize_range CVE-2022-1552
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

predicate func_1(Variable vheapRel_1009, EqualityOperation target_9) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("SetUserIdAndSecContext")
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="relowner"
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rd_rel"
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vheapRel_1009
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

predicate func_3(Variable vindexoid_1004, Variable vheapRel_1009, ExprStmt target_11, ExprStmt target_12, LogicalOrExpr target_13, ExprStmt target_14) {
	exists(LogicalAndExpr target_3 |
		target_3.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vheapRel_1009
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_3.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("pg_class_ownercheck")
		and target_3.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vindexoid_1004
		and target_3.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("Oid")
		and target_3.getParent().(IfStmt).getThen()=target_11
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_3.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_13.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_14.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
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

predicate func_7(Variable vheapoid_1007, Variable vheapRel_1009, EqualityOperation target_9, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vheapRel_1009
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("table_open")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vheapoid_1007
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="4"
		and target_7.getParent().(IfStmt).getCondition()=target_9
}

predicate func_8(Variable vindexoid_1004, FunctionCall target_8) {
		target_8.getTarget().hasName("GetUserId")
		and target_8.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("pg_class_ownercheck")
		and target_8.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vindexoid_1004
}

predicate func_9(Variable vheapoid_1007, EqualityOperation target_9) {
		target_9.getAnOperand().(VariableAccess).getTarget()=vheapoid_1007
		and target_9.getAnOperand().(Literal).getValue()="0"
}

predicate func_11(ExprStmt target_11) {
		target_11.getExpr().(FunctionCall).getTarget().hasName("aclcheck_error")
		and target_11.getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="data"
		and target_11.getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="relname"
		and target_11.getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rd_rel"
		and target_11.getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("Relation")
}

predicate func_12(Variable vindexoid_1004, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("Relation")
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("index_open")
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vindexoid_1004
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="4"
}

predicate func_13(Variable vindexoid_1004, Variable vheapoid_1007, Variable vheapRel_1009, LogicalOrExpr target_13) {
		target_13.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vheapRel_1009
		and target_13.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_13.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vheapoid_1007
		and target_13.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("IndexGetRelation")
		and target_13.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vindexoid_1004
		and target_13.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(Literal).getValue()="0"
}

predicate func_14(Variable vheapRel_1009, ExprStmt target_14) {
		target_14.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vheapRel_1009
		and target_14.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

from Function func, Variable vindexoid_1004, Variable vheapoid_1007, Variable vheapRel_1009, ExprStmt target_7, FunctionCall target_8, EqualityOperation target_9, ExprStmt target_11, ExprStmt target_12, LogicalOrExpr target_13, ExprStmt target_14
where
not func_0(target_9, func)
and not func_1(vheapRel_1009, target_9)
and not func_2(target_9, func)
and not func_3(vindexoid_1004, vheapRel_1009, target_11, target_12, target_13, target_14)
and not func_5(func)
and not func_6(func)
and func_7(vheapoid_1007, vheapRel_1009, target_9, target_7)
and func_8(vindexoid_1004, target_8)
and func_9(vheapoid_1007, target_9)
and func_11(target_11)
and func_12(vindexoid_1004, target_12)
and func_13(vindexoid_1004, vheapoid_1007, vheapRel_1009, target_13)
and func_14(vheapRel_1009, target_14)
and vindexoid_1004.getType().hasName("Oid")
and vheapoid_1007.getType().hasName("Oid")
and vheapRel_1009.getType().hasName("Relation")
and vindexoid_1004.(LocalVariable).getFunction() = func
and vheapoid_1007.(LocalVariable).getFunction() = func
and vheapRel_1009.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
