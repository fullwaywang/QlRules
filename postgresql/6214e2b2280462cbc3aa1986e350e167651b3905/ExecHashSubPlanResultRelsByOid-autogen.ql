/**
 * @name postgresql-6214e2b2280462cbc3aa1986e350e167651b3905-ExecHashSubPlanResultRelsByOid
 * @id cpp/postgresql/6214e2b2280462cbc3aa1986e350e167651b3905/ExecHashSubPlanResultRelsByOid
 * @description postgresql-6214e2b2280462cbc3aa1986e350e167651b3905-src/backend/executor/execPartition.c-ExecHashSubPlanResultRelsByOid CVE-2021-3393
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vrri_535, Parameter vmtstate_517, ExprStmt target_3, AddressOfExpr target_4) {
	exists(AssignExpr target_0 |
		target_0.getLValue().(PointerFieldAccess).getTarget().getName()="ri_RootResultRelInfo"
		and target_0.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrri_535
		and target_0.getRValue().(PointerFieldAccess).getTarget().getName()="rootResultRelInfo"
		and target_0.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmtstate_517
		and target_3.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_0.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vrri_535, VariableAccess target_1) {
		target_1.getTarget()=vrri_535
}

predicate func_2(Parameter vproute_518, Variable vrri_535, AssignExpr target_2) {
		target_2.getLValue().(PointerFieldAccess).getTarget().getName()="ri_PartitionRoot"
		and target_2.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrri_535
		and target_2.getRValue().(PointerFieldAccess).getTarget().getName()="partition_root"
		and target_2.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vproute_518
}

predicate func_3(Variable vrri_535, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="rri"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("SubplanResultRelHashElem *")
		and target_3.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vrri_535
}

predicate func_4(Parameter vmtstate_517, AddressOfExpr target_4) {
		target_4.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="resultRelInfo"
		and target_4.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmtstate_517
		and target_4.getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
}

from Function func, Parameter vproute_518, Variable vrri_535, Parameter vmtstate_517, VariableAccess target_1, AssignExpr target_2, ExprStmt target_3, AddressOfExpr target_4
where
not func_0(vrri_535, vmtstate_517, target_3, target_4)
and func_1(vrri_535, target_1)
and func_2(vproute_518, vrri_535, target_2)
and func_3(vrri_535, target_3)
and func_4(vmtstate_517, target_4)
and vproute_518.getType().hasName("PartitionTupleRouting *")
and vrri_535.getType().hasName("ResultRelInfo *")
and vmtstate_517.getType().hasName("ModifyTableState *")
and vproute_518.getFunction() = func
and vrri_535.(LocalVariable).getFunction() = func
and vmtstate_517.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
