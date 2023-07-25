/**
 * @name wireshark-02ddd49885c6a09e936a76aceb726ed06539704a-dissect_gryphon_message_with_offset
 * @id cpp/wireshark/02ddd49885c6a09e936a76aceb726ed06539704a/dissect-gryphon-message-with-offset
 * @description wireshark-02ddd49885c6a09e936a76aceb726ed06539704a-plugins/epan/gryphon/packet-gryphon.c-dissect_gryphon_message_with_offset CVE-2019-16319
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter voffset_1145, Variable vmsglen_1151, Parameter vtvb_1145, EqualityOperation target_2, ExprStmt target_3, ExprStmt target_1, ExprStmt target_4) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vmsglen_1151
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_0.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=voffset_1145
		and target_0.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("tvb_reported_length_remaining")
		and target_0.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtvb_1145
		and target_0.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=voffset_1145
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_3.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation().isBefore(target_0.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_0.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation())
		and target_0.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_1(Parameter voffset_1145, Variable vmsglen_1151, EqualityOperation target_2, ExprStmt target_1) {
		target_1.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=voffset_1145
		and target_1.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vmsglen_1151
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
}

predicate func_2(EqualityOperation target_2) {
		target_2.getAnOperand().(FunctionCall).getTarget().hasName("try_val_to_str")
		and target_2.getAnOperand().(Literal).getValue()="0"
}

predicate func_3(Parameter voffset_1145, Variable vmsglen_1151, Parameter vtvb_1145, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("proto_tree_add_item")
		and target_3.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtvb_1145
		and target_3.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=voffset_1145
		and target_3.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vmsglen_1151
		and target_3.getExpr().(FunctionCall).getArgument(5).(Literal).getValue()="0"
}

predicate func_4(Parameter voffset_1145, Parameter vtvb_1145, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("proto_tree_add_subtree")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtvb_1145
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=voffset_1145
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="8"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(StringLiteral).getValue()="Header"
}

from Function func, Parameter voffset_1145, Variable vmsglen_1151, Parameter vtvb_1145, ExprStmt target_1, EqualityOperation target_2, ExprStmt target_3, ExprStmt target_4
where
not func_0(voffset_1145, vmsglen_1151, vtvb_1145, target_2, target_3, target_1, target_4)
and func_1(voffset_1145, vmsglen_1151, target_2, target_1)
and func_2(target_2)
and func_3(voffset_1145, vmsglen_1151, vtvb_1145, target_3)
and func_4(voffset_1145, vtvb_1145, target_4)
and voffset_1145.getType().hasName("int")
and vmsglen_1151.getType().hasName("int")
and vtvb_1145.getType().hasName("tvbuff_t *")
and voffset_1145.getParentScope+() = func
and vmsglen_1151.getParentScope+() = func
and vtvb_1145.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
