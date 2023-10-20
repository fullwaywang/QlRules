/**
 * @name postgresql-6214e2b2280462cbc3aa1986e350e167651b3905-ExecInitPartitionDispatchInfo
 * @id cpp/postgresql/6214e2b2280462cbc3aa1986e350e167651b3905/ExecInitPartitionDispatchInfo
 * @description postgresql-6214e2b2280462cbc3aa1986e350e167651b3905-src/backend/executor/execPartition.c-ExecInitPartitionDispatchInfo CVE-2021-3393
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vproute_1057, ExprStmt target_3, ExprStmt target_4, Literal target_0) {
		target_0.getValue()="1"
		and not target_0.getValue()="0"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("InitResultRelInfo")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("ResultRelInfo *")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("Relation")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="partition_root"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vproute_1057
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_3.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_2(Parameter vproute_1057, ExprStmt target_3, ExprStmt target_4, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="partition_root"
		and target_2.getQualifier().(VariableAccess).getTarget()=vproute_1057
		and target_3.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getQualifier().(VariableAccess).getLocation())
		and target_2.getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_3(Parameter vproute_1057, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="partition_dispatch_info"
		and target_3.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vproute_1057
		and target_3.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
		and target_3.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget().getType().hasName("PartitionDispatch")
}

predicate func_4(Parameter vproute_1057, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="nonleaf_partitions"
		and target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vproute_1057
		and target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
		and target_4.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget().getType().hasName("ResultRelInfo *")
}

from Function func, Parameter vproute_1057, Literal target_0, PointerFieldAccess target_2, ExprStmt target_3, ExprStmt target_4
where
func_0(vproute_1057, target_3, target_4, target_0)
and func_2(vproute_1057, target_3, target_4, target_2)
and func_3(vproute_1057, target_3)
and func_4(vproute_1057, target_4)
and vproute_1057.getType().hasName("PartitionTupleRouting *")
and vproute_1057.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
