/**
 * @name linux-d7333a8ec8ca88b106a2f9729b119cb09c7e41dc-wcn36xx_set_tx_data
 * @id cpp/linux/d7333a8ec8ca88b106a2f9729b119cb09c7e41dc/wcn36xx-set-tx-data
 * @description linux-d7333a8ec8ca88b106a2f9729b119cb09c7e41dc-wcn36xx_set_tx_data CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vbd_377, Variable vis_data_qos_388) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="bd_ssn"
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pdu"
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbd_377
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vis_data_qos_388)
}

predicate func_1(Parameter vbd_377, Variable vis_data_qos_388) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="bd_ssn"
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pdu"
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbd_377
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vis_data_qos_388)
}

predicate func_2(Parameter vbd_377, Variable vhdr_384) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="bd_rate"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbd_377
		and target_2.getExpr().(AssignExpr).getRValue().(Literal).getValue()="3"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("ieee80211_is_any_nullfunc")
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="frame_control"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhdr_384)
}

predicate func_3(Parameter vbd_377, Variable vhdr_384) {
	exists(IfStmt target_3 |
		target_3.getCondition().(FunctionCall).getTarget().hasName("ieee80211_is_qos_nullfunc")
		and target_3.getCondition().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="frame_control"
		and target_3.getCondition().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhdr_384
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="bd_ssn"
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pdu"
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbd_377
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("ieee80211_is_any_nullfunc")
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="frame_control"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhdr_384)
}

predicate func_4(Parameter vbd_377, Variable vhdr_384) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="queue_id"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbd_377
		and target_4.getExpr().(AssignExpr).getRValue().(Literal).getValue()="9"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("ieee80211_is_any_nullfunc")
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="frame_control"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhdr_384)
}

predicate func_5(Parameter vbd_377) {
	exists(PointerFieldAccess target_5 |
		target_5.getTarget().getName()="queue_id"
		and target_5.getQualifier().(VariableAccess).getTarget()=vbd_377)
}

predicate func_6(Parameter vbd_377) {
	exists(PointerFieldAccess target_6 |
		target_6.getTarget().getName()="dpu_ne"
		and target_6.getQualifier().(VariableAccess).getTarget()=vbd_377)
}

predicate func_7(Variable vhdr_384) {
	exists(PointerFieldAccess target_7 |
		target_7.getTarget().getName()="frame_control"
		and target_7.getQualifier().(VariableAccess).getTarget()=vhdr_384)
}

from Function func, Parameter vbd_377, Variable vhdr_384, Variable vis_data_qos_388
where
not func_0(vbd_377, vis_data_qos_388)
and not func_1(vbd_377, vis_data_qos_388)
and not func_2(vbd_377, vhdr_384)
and not func_3(vbd_377, vhdr_384)
and func_4(vbd_377, vhdr_384)
and vbd_377.getType().hasName("wcn36xx_tx_bd *")
and func_5(vbd_377)
and func_6(vbd_377)
and vhdr_384.getType().hasName("ieee80211_hdr *")
and func_7(vhdr_384)
and vis_data_qos_388.getType().hasName("bool")
and vbd_377.getParentScope+() = func
and vhdr_384.getParentScope+() = func
and vis_data_qos_388.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
