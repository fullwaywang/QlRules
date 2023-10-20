/**
 * @name wireshark-00d5e9e9fb377f52ab7696f25c1dbc011ef0244d-dissect_compressed_beamforming_and_cqi
 * @id cpp/wireshark/00d5e9e9fb377f52ab7696f25c1dbc011ef0244d/dissect-compressed-beamforming-and-cqi
 * @description wireshark-00d5e9e9fb377f52ab7696f25c1dbc011ef0244d-epan/dissectors/packet-ieee80211.c-dissect_compressed_beamforming_and_cqi CVE-2019-10897
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpinfo_12309, Variable vbit_offset_12314, Parameter vtree_12309, ExprStmt target_1, ExprStmt target_2, ExprStmt target_3) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbit_offset_12314
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("int")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("expert_add_info")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpinfo_12309
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtree_12309
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("expert_field")
		and target_0.getThen().(BlockStmt).getStmt(1).(BreakStmt).toString() = "break;"
		and target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_1(Variable vbit_offset_12314, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbit_offset_12314
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("dissect_he_feedback_matrix")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vbit_offset_12314
}

predicate func_2(Variable vbit_offset_12314, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vbit_offset_12314
		and target_2.getExpr().(AssignExpr).getRValue().(DivExpr).getRightOperand().(Literal).getValue()="8"
}

predicate func_3(Parameter vtree_12309, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("proto_tree_add_subtree")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtree_12309
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(UnaryMinusExpr).getValue()="-1"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(StringLiteral).getValue()="Feedback Matrices"
}

from Function func, Parameter vpinfo_12309, Variable vbit_offset_12314, Parameter vtree_12309, ExprStmt target_1, ExprStmt target_2, ExprStmt target_3
where
not func_0(vpinfo_12309, vbit_offset_12314, vtree_12309, target_1, target_2, target_3)
and func_1(vbit_offset_12314, target_1)
and func_2(vbit_offset_12314, target_2)
and func_3(vtree_12309, target_3)
and vpinfo_12309.getType().hasName("packet_info *")
and vbit_offset_12314.getType().hasName("int")
and vtree_12309.getType().hasName("proto_tree *")
and vpinfo_12309.getParentScope+() = func
and vbit_offset_12314.getParentScope+() = func
and vtree_12309.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
