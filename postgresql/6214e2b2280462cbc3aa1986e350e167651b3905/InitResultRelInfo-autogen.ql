/**
 * @name postgresql-6214e2b2280462cbc3aa1986e350e167651b3905-InitResultRelInfo
 * @id cpp/postgresql/6214e2b2280462cbc3aa1986e350e167651b3905/InitResultRelInfo
 * @description postgresql-6214e2b2280462cbc3aa1986e350e167651b3905-src/backend/executor/execMain.c-InitResultRelInfo CVE-2021-3393
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vresultRelInfo_1196, ExprStmt target_3, ExprStmt target_4) {
	exists(AssignExpr target_0 |
		target_0.getLValue().(PointerFieldAccess).getTarget().getName()="ri_RootResultRelInfo"
		and target_0.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelInfo_1196
		and target_0.getRValue().(VariableAccess).getType().hasName("ResultRelInfo *")
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vresultRelInfo_1196, VariableAccess target_1) {
		target_1.getTarget()=vresultRelInfo_1196
}

predicate func_2(Parameter vpartition_root_1199, Parameter vresultRelInfo_1196, AssignExpr target_2) {
		target_2.getLValue().(PointerFieldAccess).getTarget().getName()="ri_PartitionRoot"
		and target_2.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelInfo_1196
		and target_2.getRValue().(VariableAccess).getTarget()=vpartition_root_1199
}

predicate func_3(Parameter vresultRelInfo_1196, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ri_TrigNewSlot"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelInfo_1196
		and target_3.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_4(Parameter vresultRelInfo_1196, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ri_RootToPartitionMap"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelInfo_1196
		and target_4.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

from Function func, Parameter vpartition_root_1199, Parameter vresultRelInfo_1196, VariableAccess target_1, AssignExpr target_2, ExprStmt target_3, ExprStmt target_4
where
not func_0(vresultRelInfo_1196, target_3, target_4)
and func_1(vresultRelInfo_1196, target_1)
and func_2(vpartition_root_1199, vresultRelInfo_1196, target_2)
and func_3(vresultRelInfo_1196, target_3)
and func_4(vresultRelInfo_1196, target_4)
and vpartition_root_1199.getType().hasName("Relation")
and vresultRelInfo_1196.getType().hasName("ResultRelInfo *")
and vpartition_root_1199.getFunction() = func
and vresultRelInfo_1196.getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
