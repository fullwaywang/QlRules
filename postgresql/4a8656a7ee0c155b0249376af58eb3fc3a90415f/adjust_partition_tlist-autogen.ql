/**
 * @name postgresql-4a8656a7ee0c155b0249376af58eb3fc3a90415f-adjust_partition_tlist
 * @id cpp/postgresql/4a8656a7ee0c155b0249376af58eb3fc3a90415f/adjust-partition-tlist
 * @description postgresql-4a8656a7ee0c155b0249376af58eb3fc3a90415f-src/backend/executor/execPartition.c-adjust_partition_tlist CVE-2021-32028
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vattrno_1509, VariableAccess target_0) {
		target_0.getTarget()=vattrno_1509
		and target_0.getParent().(SubExpr).getParent().(ArrayExpr).getParent().(SubExpr).getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("list_nth")
		and target_0.getParent().(SubExpr).getParent().(ArrayExpr).getParent().(SubExpr).getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("List *")
		and target_0.getParent().(SubExpr).getParent().(ArrayExpr).getParent().(SubExpr).getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1) instanceof SubExpr
}

predicate func_2(EqualityOperation target_8, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(Literal).getValue()="1"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(EqualityOperation target_8, Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(Literal).getValue()="1"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Variable vnew_tlist_1506, Function func) {
	exists(ForStmt target_4 |
		target_4.getCondition().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="l"
		and target_4.getCondition().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("ForEachState")
		and target_4.getCondition().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_4.getCondition().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="i"
		and target_4.getCondition().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("ForEachState")
		and target_4.getCondition().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="length"
		and target_4.getCondition().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="l"
		and target_4.getCondition().(ConditionalExpr).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("ForEachState")
		and target_4.getCondition().(ConditionalExpr).getThen().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(VariableAccess).getType().hasName("ListCell *")
		and target_4.getCondition().(ConditionalExpr).getThen().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="elements"
		and target_4.getCondition().(ConditionalExpr).getThen().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(ValueFieldAccess).getTarget().getName()="i"
		and target_4.getCondition().(ConditionalExpr).getThen().(CommaExpr).getRightOperand() instanceof Literal
		and target_4.getCondition().(ConditionalExpr).getElse().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(VariableAccess).getType().hasName("ListCell *")
		and target_4.getCondition().(ConditionalExpr).getElse().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_4.getCondition().(ConditionalExpr).getElse().(CommaExpr).getRightOperand().(Literal).getValue()="0"
		and target_4.getUpdate().(PostfixIncrExpr).getOperand().(ValueFieldAccess).getTarget().getName()="i"
		and target_4.getUpdate().(PostfixIncrExpr).getOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("ForEachState")
		and target_4.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="resjunk"
		and target_4.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("TargetEntry *")
		and target_4.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="resno"
		and target_4.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnew_tlist_1506
		and target_4.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("lappend")
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_4))
}

predicate func_5(Variable vattrMap_1508, Variable vattrno_1509, BlockStmt target_9, ArrayExpr target_5) {
		target_5.getArrayBase().(PointerFieldAccess).getTarget().getName()="attnums"
		and target_5.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vattrMap_1508
		and target_5.getArrayOffset().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vattrno_1509
		and target_5.getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_5.getParent().(NEExpr).getAnOperand().(Literal).getValue()="0"
		and target_5.getParent().(NEExpr).getParent().(IfStmt).getThen()=target_9
}

predicate func_7(Variable vattrMap_1508, Variable vattrno_1509, SubExpr target_7) {
		target_7.getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="attnums"
		and target_7.getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vattrMap_1508
		and target_7.getLeftOperand().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vattrno_1509
		and target_7.getLeftOperand().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_7.getRightOperand() instanceof Literal
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("list_nth")
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("List *")
}

predicate func_8(EqualityOperation target_8) {
		target_8.getAnOperand() instanceof ArrayExpr
		and target_8.getAnOperand().(Literal).getValue()="0"
}

predicate func_9(BlockStmt target_9) {
		target_9.getStmt(0).(ExprStmt).getExpr().(Literal).getValue()="1"
		and target_9.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("TargetEntry *")
		and target_9.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("list_nth")
		and target_9.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("List *")
		and target_9.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1) instanceof SubExpr
}

from Function func, Variable vnew_tlist_1506, Variable vattrMap_1508, Variable vattrno_1509, VariableAccess target_0, ArrayExpr target_5, SubExpr target_7, EqualityOperation target_8, BlockStmt target_9
where
func_0(vattrno_1509, target_0)
and not func_2(target_8, func)
and not func_3(target_8, func)
and not func_4(vnew_tlist_1506, func)
and func_5(vattrMap_1508, vattrno_1509, target_9, target_5)
and func_7(vattrMap_1508, vattrno_1509, target_7)
and func_8(target_8)
and func_9(target_9)
and vnew_tlist_1506.getType().hasName("List *")
and vattrMap_1508.getType().hasName("AttrMap *")
and vattrno_1509.getType().hasName("AttrNumber")
and vnew_tlist_1506.(LocalVariable).getFunction() = func
and vattrMap_1508.(LocalVariable).getFunction() = func
and vattrno_1509.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
