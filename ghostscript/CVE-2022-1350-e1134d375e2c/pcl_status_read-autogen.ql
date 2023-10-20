/**
 * @name ghostscript-e1134d375e2c-pcl_status_read
 * @id cpp/ghostscript/e1134d375e2c/pcl-status-read
 * @description ghostscript-e1134d375e2c-pcl/pcl/pcstatus.c-pcl_status_read CVE-2022-1350
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpcs_45, EqualityOperation target_1, ValueFieldAccess target_2, ExprStmt target_3) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="buffer"
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="status"
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpcs_45
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vpcs_45, EqualityOperation target_1) {
		target_1.getAnOperand().(ValueFieldAccess).getTarget().getName()="read_pos"
		and target_1.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="status"
		and target_1.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpcs_45
		and target_1.getAnOperand().(ValueFieldAccess).getTarget().getName()="write_pos"
		and target_1.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="status"
		and target_1.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpcs_45
}

predicate func_2(Parameter vpcs_45, ValueFieldAccess target_2) {
		target_2.getTarget().getName()="buffer"
		and target_2.getQualifier().(PointerFieldAccess).getTarget().getName()="status"
		and target_2.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpcs_45
}

predicate func_3(Parameter vpcs_45, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="write_pos"
		and target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="status"
		and target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpcs_45
		and target_3.getExpr().(AssignExpr).getRValue().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="read_pos"
		and target_3.getExpr().(AssignExpr).getRValue().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="status"
		and target_3.getExpr().(AssignExpr).getRValue().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpcs_45
		and target_3.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(Literal).getValue()="0"
}

from Function func, Parameter vpcs_45, EqualityOperation target_1, ValueFieldAccess target_2, ExprStmt target_3
where
not func_0(vpcs_45, target_1, target_2, target_3)
and func_1(vpcs_45, target_1)
and func_2(vpcs_45, target_2)
and func_3(vpcs_45, target_3)
and vpcs_45.getType().hasName("pcl_state_t *")
and vpcs_45.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
