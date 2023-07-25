/**
 * @name wireshark-e6e98eab8e5e0bbc982cfdc808f2469d7cab6c5a-nfs_name_snoop_fh
 * @id cpp/wireshark/e6e98eab8e5e0bbc982cfdc808f2469d7cab6c5a/nfs-name-snoop-fh
 * @description wireshark-e6e98eab8e5e0bbc982cfdc808f2469d7cab6c5a-epan/dissectors/packet-nfs.c-nfs_name_snoop_fh CVE-2020-13164
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Parameter vtvb_1248, Variable vnns_1252, Parameter vpinfo_1248, Parameter vtree_1248, VariableAccess target_2, ExprStmt target_3) {
	exists(IfStmt target_1 |
		target_1.getCondition().(PointerFieldAccess).getTarget().getName()="fs_cycle"
		and target_1.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnns_1252
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("proto_tree_add_expert")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtree_1248
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpinfo_1248
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("expert_field")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vtvb_1248
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(4)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation()))
}

predicate func_2(Variable vnns_1252, VariableAccess target_2) {
		target_2.getTarget()=vnns_1252
}

predicate func_3(Parameter vtvb_1248, Variable vnns_1252, Parameter vtree_1248, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("proto_tree_add_string_format_value")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtree_1248
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtvb_1248
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="full_name"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnns_1252
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(StringLiteral).getValue()="%s"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="full_name"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnns_1252
}

from Function func, Parameter vtvb_1248, Variable vnns_1252, Parameter vpinfo_1248, Parameter vtree_1248, VariableAccess target_2, ExprStmt target_3
where
not func_1(vtvb_1248, vnns_1252, vpinfo_1248, vtree_1248, target_2, target_3)
and func_2(vnns_1252, target_2)
and func_3(vtvb_1248, vnns_1252, vtree_1248, target_3)
and vtvb_1248.getType().hasName("tvbuff_t *")
and vnns_1252.getType().hasName("nfs_name_snoop_t *")
and vpinfo_1248.getType().hasName("packet_info *")
and vtree_1248.getType().hasName("proto_tree *")
and vtvb_1248.getParentScope+() = func
and vnns_1252.getParentScope+() = func
and vpinfo_1248.getParentScope+() = func
and vtree_1248.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
