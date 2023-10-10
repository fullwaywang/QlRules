/**
 * @name wireshark-eafdcfa4b6d5187a5326442a82608ab03d9dddcb-dissect_spoolss_buffer_data
 * @id cpp/wireshark/eafdcfa4b6d5187a5326442a82608ab03d9dddcb/dissect-spoolss-buffer-data
 * @description wireshark-eafdcfa4b6d5187a5326442a82608ab03d9dddcb-epan/dissectors/packet-dcerpc-spoolss.c-dissect_spoolss_buffer_data CVE-2019-10903
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtvb_440, Parameter voffset_440, Parameter vpinfo_440, Parameter vtree_441, Variable vsize_445, ExprStmt target_1, ExprStmt target_2, ExprStmt target_3, AddressOfExpr target_4, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("tvb_reported_length_remaining")
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtvb_440
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=voffset_440
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vsize_445
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("expert_add_info")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpinfo_440
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtree_441
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("expert_field")
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(VariableAccess).getTarget()=voffset_440
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_4.getOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vtvb_440, Parameter voffset_440, Parameter vpinfo_440, Parameter vtree_441, Variable vsize_445, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=voffset_440
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("dissect_ndr_uint32")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtvb_440
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=voffset_440
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vpinfo_440
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vtree_441
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vsize_445
}

predicate func_2(Parameter vtvb_440, Parameter voffset_440, Parameter vpinfo_440, Variable vsize_445, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=voffset_440
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("dissect_ndr_uint8s")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtvb_440
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=voffset_440
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vpinfo_440
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vsize_445
}

predicate func_3(Parameter vtvb_440, Parameter voffset_440, Parameter vtree_441, Variable vsize_445, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("proto_tree_add_item")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtree_441
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtvb_440
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(SubExpr).getLeftOperand().(VariableAccess).getTarget()=voffset_440
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(SubExpr).getRightOperand().(VariableAccess).getTarget()=vsize_445
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vsize_445
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(Literal).getValue()="0"
}

predicate func_4(Variable vsize_445, AddressOfExpr target_4) {
		target_4.getOperand().(VariableAccess).getTarget()=vsize_445
}

from Function func, Parameter vtvb_440, Parameter voffset_440, Parameter vpinfo_440, Parameter vtree_441, Variable vsize_445, ExprStmt target_1, ExprStmt target_2, ExprStmt target_3, AddressOfExpr target_4
where
not func_0(vtvb_440, voffset_440, vpinfo_440, vtree_441, vsize_445, target_1, target_2, target_3, target_4, func)
and func_1(vtvb_440, voffset_440, vpinfo_440, vtree_441, vsize_445, target_1)
and func_2(vtvb_440, voffset_440, vpinfo_440, vsize_445, target_2)
and func_3(vtvb_440, voffset_440, vtree_441, vsize_445, target_3)
and func_4(vsize_445, target_4)
and vtvb_440.getType().hasName("tvbuff_t *")
and voffset_440.getType().hasName("int")
and vpinfo_440.getType().hasName("packet_info *")
and vtree_441.getType().hasName("proto_tree *")
and vsize_445.getType().hasName("guint32")
and vtvb_440.getParentScope+() = func
and voffset_440.getParentScope+() = func
and vpinfo_440.getParentScope+() = func
and vtree_441.getParentScope+() = func
and vsize_445.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
