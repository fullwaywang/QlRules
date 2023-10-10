/**
 * @name postgresql-6214e2b2280462cbc3aa1986e350e167651b3905-ExecInitPartitionInfo
 * @id cpp/postgresql/6214e2b2280462cbc3aa1986e350e167651b3905/ExecInitPartitionInfo
 * @description postgresql-6214e2b2280462cbc3aa1986e350e167651b3905-src/backend/executor/execPartition.c-ExecInitPartitionInfo CVE-2021-3393
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vleaf_part_rri_573, PointerFieldAccess target_10, ExprStmt target_11, PointerFieldAccess target_0) {
		target_0.getTarget().getName()="ri_PartitionRoot"
		and target_0.getQualifier().(VariableAccess).getTarget()=vleaf_part_rri_573
		and target_10.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getQualifier().(VariableAccess).getLocation())
		and target_0.getQualifier().(VariableAccess).getLocation().isBefore(target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
}

predicate func_2(Parameter vrootResultRelInfo_566, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="ri_RelationDesc"
		and target_2.getQualifier().(VariableAccess).getTarget()=vrootResultRelInfo_566
}

predicate func_3(LogicalAndExpr target_12, Function func, DeclStmt target_3) {
		target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_12
		and target_3.getEnclosingFunction() = func
}

predicate func_6(Variable vnode_569, Variable vrootrel_570, Variable vleaf_part_rri_573, ConditionalExpr target_6) {
		target_6.getCondition().(VariableAccess).getTarget()=vnode_569
		and target_6.getThen().(PointerFieldAccess).getTarget().getName()="rootRelation"
		and target_6.getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnode_569
		and target_6.getElse().(Literal).getValue()="1"
		and target_6.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("InitResultRelInfo")
		and target_6.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vleaf_part_rri_573
		and target_6.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("Relation")
		and target_6.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vrootrel_570
		and target_6.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="es_instrument"
		and target_6.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("EState *")
}

/*predicate func_7(Variable vnode_569, Variable vrootrel_570, Variable vleaf_part_rri_573, VariableAccess target_7) {
		target_7.getTarget()=vrootrel_570
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("InitResultRelInfo")
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vleaf_part_rri_573
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("Relation")
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getCondition().(VariableAccess).getTarget()=vnode_569
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getThen().(PointerFieldAccess).getTarget().getName()="rootRelation"
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnode_569
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(ConditionalExpr).getElse().(Literal).getValue()="1"
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="es_instrument"
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("EState *")
}

*/
predicate func_8(LogicalAndExpr target_13, Function func, DeclStmt target_8) {
		target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
		and target_8.getEnclosingFunction() = func
}

predicate func_9(LogicalAndExpr target_14, Function func, DeclStmt target_9) {
		target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14
		and target_9.getEnclosingFunction() = func
}

predicate func_10(Variable vleaf_part_rri_573, PointerFieldAccess target_10) {
		target_10.getTarget().getName()="rd_att"
		and target_10.getQualifier().(PointerFieldAccess).getTarget().getName()="ri_RelationDesc"
		and target_10.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vleaf_part_rri_573
}

predicate func_11(Variable vleaf_part_rri_573, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="es_tuple_routing_result_relations"
		and target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("EState *")
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("lappend")
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="es_tuple_routing_result_relations"
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("EState *")
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vleaf_part_rri_573
}

predicate func_12(Variable vnode_569, LogicalAndExpr target_12) {
		target_12.getAnOperand().(VariableAccess).getTarget()=vnode_569
		and target_12.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="withCheckOptionLists"
		and target_12.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnode_569
		and target_12.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

predicate func_13(Variable vnode_569, LogicalAndExpr target_13) {
		target_13.getAnOperand().(VariableAccess).getTarget()=vnode_569
		and target_13.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="returningLists"
		and target_13.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnode_569
		and target_13.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

predicate func_14(Variable vnode_569, LogicalAndExpr target_14) {
		target_14.getAnOperand().(VariableAccess).getTarget()=vnode_569
		and target_14.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="onConflictAction"
		and target_14.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnode_569
}

from Function func, Parameter vrootResultRelInfo_566, Variable vnode_569, Variable vrootrel_570, Variable vleaf_part_rri_573, PointerFieldAccess target_0, PointerFieldAccess target_2, DeclStmt target_3, ConditionalExpr target_6, DeclStmt target_8, DeclStmt target_9, PointerFieldAccess target_10, ExprStmt target_11, LogicalAndExpr target_12, LogicalAndExpr target_13, LogicalAndExpr target_14
where
func_0(vleaf_part_rri_573, target_10, target_11, target_0)
and func_2(vrootResultRelInfo_566, target_2)
and func_3(target_12, func, target_3)
and func_6(vnode_569, vrootrel_570, vleaf_part_rri_573, target_6)
and func_8(target_13, func, target_8)
and func_9(target_14, func, target_9)
and func_10(vleaf_part_rri_573, target_10)
and func_11(vleaf_part_rri_573, target_11)
and func_12(vnode_569, target_12)
and func_13(vnode_569, target_13)
and func_14(vnode_569, target_14)
and vrootResultRelInfo_566.getType().hasName("ResultRelInfo *")
and vnode_569.getType().hasName("ModifyTable *")
and vrootrel_570.getType().hasName("Relation")
and vleaf_part_rri_573.getType().hasName("ResultRelInfo *")
and vrootResultRelInfo_566.getFunction() = func
and vnode_569.(LocalVariable).getFunction() = func
and vrootrel_570.(LocalVariable).getFunction() = func
and vleaf_part_rri_573.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
