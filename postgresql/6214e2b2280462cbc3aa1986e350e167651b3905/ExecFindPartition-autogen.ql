/**
 * @name postgresql-6214e2b2280462cbc3aa1986e350e167651b3905-ExecFindPartition
 * @id cpp/postgresql/6214e2b2280462cbc3aa1986e350e167651b3905/ExecFindPartition
 * @description postgresql-6214e2b2280462cbc3aa1986e350e167651b3905-src/backend/executor/execPartition.c-ExecFindPartition CVE-2021-3393
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Parameter vmtstate_277, ExprStmt target_4) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="rootResultRelInfo"
		and target_1.getQualifier().(VariableAccess).getTarget()=vmtstate_277
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vmtstate_277, VariableAccess target_2) {
		target_2.getTarget()=vmtstate_277
		and target_2.getParent().(PointerFieldAccess).getParent().(ValueFieldAccess).getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ExecInitPartitionDispatchInfo")
		and target_2.getParent().(PointerFieldAccess).getParent().(ValueFieldAccess).getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0) instanceof ValueFieldAccess
		and target_2.getParent().(PointerFieldAccess).getParent().(ValueFieldAccess).getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("PartitionTupleRouting *")
		and target_2.getParent().(PointerFieldAccess).getParent().(ValueFieldAccess).getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="oids"
		and target_2.getParent().(PointerFieldAccess).getParent().(ValueFieldAccess).getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("PartitionDesc")
		and target_2.getParent().(PointerFieldAccess).getParent().(ValueFieldAccess).getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
		and target_2.getParent().(PointerFieldAccess).getParent().(ValueFieldAccess).getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("PartitionDispatch")
		and target_2.getParent().(PointerFieldAccess).getParent().(ValueFieldAccess).getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_3(Parameter vmtstate_277, ValueFieldAccess target_3) {
		target_3.getTarget().getName()="state"
		and target_3.getQualifier().(PointerFieldAccess).getTarget().getName()="ps"
		and target_3.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmtstate_277
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ExecInitPartitionDispatchInfo")
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("PartitionTupleRouting *")
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="oids"
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("PartitionDesc")
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("PartitionDispatch")
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_4(Parameter vmtstate_277, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("ResultRelInfo *")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ExecInitPartitionInfo")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmtstate_277
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("EState *")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("PartitionTupleRouting *")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("PartitionDispatch")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget().getType().hasName("ResultRelInfo *")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget().getType().hasName("int")
}

from Function func, Parameter vmtstate_277, VariableAccess target_2, ValueFieldAccess target_3, ExprStmt target_4
where
not func_1(vmtstate_277, target_4)
and func_2(vmtstate_277, target_2)
and func_3(vmtstate_277, target_3)
and func_4(vmtstate_277, target_4)
and vmtstate_277.getType().hasName("ModifyTableState *")
and vmtstate_277.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
