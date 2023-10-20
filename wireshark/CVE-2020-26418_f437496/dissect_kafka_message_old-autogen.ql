/**
 * @name wireshark-f4374967bbf9c12746b8ec3cd54dddada9dd353e-dissect_kafka_message_old
 * @id cpp/wireshark/f4374967bbf9c12746b8ec3cd54dddada9dd353e/dissect-kafka-message-old
 * @description wireshark-f4374967bbf9c12746b8ec3cd54dddada9dd353e-epan/dissectors/packet-kafka.c-dissect_kafka_message_old CVE-2020-26418
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vlength_1916, Parameter voffset_1905, EqualityOperation target_1, ExprStmt target_0) {
		target_0.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=voffset_1905
		and target_0.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vlength_1916
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
}

predicate func_1(EqualityOperation target_1) {
		target_1.getAnOperand().(Literal).getValue()="0"
}

from Function func, Variable vlength_1916, Parameter voffset_1905, ExprStmt target_0, EqualityOperation target_1
where
func_0(vlength_1916, voffset_1905, target_1, target_0)
and func_1(target_1)
and vlength_1916.getType().hasName("guint32")
and voffset_1905.getType().hasName("int")
and vlength_1916.getParentScope+() = func
and voffset_1905.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
