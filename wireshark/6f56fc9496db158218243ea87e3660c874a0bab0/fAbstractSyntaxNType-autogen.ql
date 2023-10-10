/**
 * @name wireshark-6f56fc9496db158218243ea87e3660c874a0bab0-fAbstractSyntaxNType
 * @id cpp/wireshark/6f56fc9496db158218243ea87e3660c874a0bab0/fAbstractSyntaxNType
 * @description wireshark-6f56fc9496db158218243ea87e3660c874a0bab0-epan/dissectors/packet-bacapp.c-fAbstractSyntaxNType CVE-2020-11647
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtvb_7972, Parameter vpinfo_7972, Parameter vtree_7972, Parameter voffset_7972, RelationalOperation target_5, ExprStmt target_6, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(PrefixIncrExpr).getOperand().(VariableAccess).getType().hasName("unsigned int")
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="100"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("proto_tree_add_expert")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtree_7972
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpinfo_7972
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("expert_field")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vtvb_7972
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(VariableAccess).getTarget()=voffset_7972
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_0)
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation().isBefore(target_5.getGreaterOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vpinfo_7972, ExprStmt target_7, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("p_add_proto_data")
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="pool"
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpinfo_7972
		and target_1.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpinfo_7972
		and target_1.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getType().hasName("int")
		and target_1.getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_1.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getType().hasName("unsigned int")
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_1)
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_2(Parameter vpinfo_7972, ExprStmt target_8, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("unsigned int")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("p_get_proto_data")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="pool"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpinfo_7972
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpinfo_7972
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getType().hasName("int")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_2)
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getType().hasName("unsigned int")
		and (func.getEntryPoint().(BlockStmt).getStmt(12)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(12).getFollowingStmt()=target_3))
}

predicate func_4(Parameter vpinfo_7972, Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(FunctionCall).getTarget().hasName("p_add_proto_data")
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="pool"
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpinfo_7972
		and target_4.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpinfo_7972
		and target_4.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getType().hasName("int")
		and target_4.getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_4.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getType().hasName("unsigned int")
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_4))
}

predicate func_5(Parameter vtvb_7972, Parameter voffset_7972, RelationalOperation target_5) {
		 (target_5 instanceof GTExpr or target_5 instanceof LTExpr)
		and target_5.getGreaterOperand().(FunctionCall).getTarget().hasName("tvb_reported_length_remaining")
		and target_5.getGreaterOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtvb_7972
		and target_5.getGreaterOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=voffset_7972
		and target_5.getLesserOperand().(Literal).getValue()="0"
}

predicate func_6(Parameter vtvb_7972, Parameter vpinfo_7972, Parameter vtree_7972, Parameter voffset_7972, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=voffset_7972
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("fApplicationTypesEnumerated")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtvb_7972
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpinfo_7972
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtree_7972
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=voffset_7972
}

predicate func_7(Parameter vtvb_7972, Parameter vpinfo_7972, Parameter voffset_7972, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("fTagHeader")
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtvb_7972
		and target_7.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpinfo_7972
		and target_7.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=voffset_7972
}

predicate func_8(Parameter vtvb_7972, Parameter vpinfo_7972, Parameter vtree_7972, Parameter voffset_7972, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=voffset_7972
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("fApplicationTypes")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtvb_7972
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpinfo_7972
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtree_7972
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=voffset_7972
}

from Function func, Parameter vtvb_7972, Parameter vpinfo_7972, Parameter vtree_7972, Parameter voffset_7972, RelationalOperation target_5, ExprStmt target_6, ExprStmt target_7, ExprStmt target_8
where
not func_0(vtvb_7972, vpinfo_7972, vtree_7972, voffset_7972, target_5, target_6, func)
and not func_1(vpinfo_7972, target_7, func)
and not func_2(vpinfo_7972, target_8, func)
and not func_3(func)
and not func_4(vpinfo_7972, func)
and func_5(vtvb_7972, voffset_7972, target_5)
and func_6(vtvb_7972, vpinfo_7972, vtree_7972, voffset_7972, target_6)
and func_7(vtvb_7972, vpinfo_7972, voffset_7972, target_7)
and func_8(vtvb_7972, vpinfo_7972, vtree_7972, voffset_7972, target_8)
and vtvb_7972.getType().hasName("tvbuff_t *")
and vpinfo_7972.getType().hasName("packet_info *")
and vtree_7972.getType().hasName("proto_tree *")
and voffset_7972.getType().hasName("guint")
and vtvb_7972.getParentScope+() = func
and vpinfo_7972.getParentScope+() = func
and vtree_7972.getParentScope+() = func
and voffset_7972.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
