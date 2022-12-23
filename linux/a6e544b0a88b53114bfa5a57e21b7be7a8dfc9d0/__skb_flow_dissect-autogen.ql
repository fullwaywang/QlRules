/**
 * @name linux-a6e544b0a88b53114bfa5a57e21b7be7a8dfc9d0-__skb_flow_dissect
 * @id cpp/linux/a6e544b0a88b53114bfa5a57e21b7be7a8dfc9d0/__skb_flow_dissect
 * @description linux-a6e544b0a88b53114bfa5a57e21b7be7a8dfc9d0-__skb_flow_dissect 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(DeclStmt target_0 |
		target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr() instanceof EnumConstantAccess
		and func.getEntryPoint().(BlockStmt).getStmt(7)=target_0)
}

predicate func_1(Variable viph_169) {
	exists(GotoStmt target_1 |
		target_1.toString() = "goto ..."
		and target_1.getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=viph_169
		and target_1.getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="ihl"
		and target_1.getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viph_169
		and target_1.getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="5")
}

predicate func_16(Function func) {
	exists(LabelStmt target_16 |
		target_16.toString() = "label ...:"
		and (func.getEntryPoint().(BlockStmt).getStmt(19)=target_16 or func.getEntryPoint().(BlockStmt).getStmt(19).getFollowingStmt()=target_16))
}

predicate func_17(Function func) {
	exists(AssignExpr target_17 |
		target_17.getLValue().(VariableAccess).getType().hasName("bool")
		and target_17.getRValue() instanceof EnumConstantAccess
		and target_17.getEnclosingFunction() = func)
}

predicate func_20(Parameter vproto_124, Variable vkey_basic_127) {
	exists(ExprStmt target_20 |
		target_20.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="n_proto"
		and target_20.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_basic_127
		and target_20.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vproto_124)
}

predicate func_21(Parameter vnhoff_124, Variable vkey_control_126) {
	exists(ExprStmt target_21 |
		target_21.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="thoff"
		and target_21.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_control_126
		and target_21.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vnhoff_124)
}

predicate func_22(Variable vkey_basic_127, Variable vip_proto_132, Variable vhdr_295) {
	exists(ExprStmt target_22 |
		target_22.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ip_proto"
		and target_22.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_basic_127
		and target_22.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vip_proto_132
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ConditionalExpr).getCondition().(FunctionCall).getTarget().hasName("__builtin_constant_p")
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ConditionalExpr).getCondition().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="entry"
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ConditionalExpr).getCondition().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vhdr_295
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ConditionalExpr).getCondition().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ConditionalExpr).getThen().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="entry"
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ConditionalExpr).getThen().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vhdr_295
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ConditionalExpr).getThen().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ConditionalExpr).getThen().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="255"
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ConditionalExpr).getThen().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="24"
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ConditionalExpr).getThen().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="entry"
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ConditionalExpr).getThen().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vhdr_295
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ConditionalExpr).getThen().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ConditionalExpr).getThen().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="65280"
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ConditionalExpr).getThen().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ConditionalExpr).getThen().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="entry"
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ConditionalExpr).getThen().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vhdr_295
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ConditionalExpr).getThen().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ConditionalExpr).getThen().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="16711680"
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ConditionalExpr).getThen().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ConditionalExpr).getThen().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="entry"
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ConditionalExpr).getThen().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vhdr_295
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ConditionalExpr).getThen().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ConditionalExpr).getThen().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="4278190080"
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ConditionalExpr).getThen().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="24"
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ConditionalExpr).getElse().(FunctionCall).getTarget().hasName("__fswab32")
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="entry"
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vhdr_295
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="4294963200"
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="12"
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="7")
}

predicate func_23(Variable vkey_control_126) {
	exists(PointerFieldAccess target_23 |
		target_23.getTarget().getName()="thoff"
		and target_23.getQualifier().(VariableAccess).getTarget()=vkey_control_126)
}

predicate func_31(Variable viph_169) {
	exists(ReturnStmt target_31 |
		target_31.getExpr() instanceof EnumConstantAccess
		and target_31.getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=viph_169
		and target_31.getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="ihl"
		and target_31.getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viph_169
		and target_31.getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="5")
}

predicate func_37(Function func) {
	exists(ReturnStmt target_37 |
		target_37.getExpr() instanceof EnumConstantAccess
		and target_37.getEnclosingFunction() = func)
}

predicate func_48(Parameter vproto_124, Variable vkey_basic_127) {
	exists(AssignExpr target_48 |
		target_48.getLValue().(PointerFieldAccess).getTarget().getName()="n_proto"
		and target_48.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_basic_127
		and target_48.getRValue().(VariableAccess).getTarget()=vproto_124)
}

from Function func, Parameter vproto_124, Parameter vnhoff_124, Variable vkey_control_126, Variable vkey_basic_127, Variable vip_proto_132, Variable viph_169, Variable viph_193, Variable vvlan_232, Variable vhdr_256, Variable vhdr_275, Variable vhdr_295, Variable vhdr_336, Variable vkeyid_353, Variable veth_374, Variable vopthdr_390
where
not func_0(func)
and not func_1(viph_169)
and not func_16(func)
and not func_17(func)
and func_20(vproto_124, vkey_basic_127)
and func_21(vnhoff_124, vkey_control_126)
and func_22(vkey_basic_127, vip_proto_132, vhdr_295)
and func_23(vkey_control_126)
and func_31(viph_169)
and func_37(func)
and func_48(vproto_124, vkey_basic_127)
and vproto_124.getType().hasName("__be16")
and vnhoff_124.getType().hasName("int")
and vkey_control_126.getType().hasName("flow_dissector_key_control *")
and vkey_basic_127.getType().hasName("flow_dissector_key_basic *")
and vip_proto_132.getType().hasName("u8")
and viph_169.getType().hasName("const iphdr *")
and viph_193.getType().hasName("const ipv6hdr *")
and vvlan_232.getType().hasName("const vlan_hdr *")
and vhdr_256.getType().hasName("struct <unnamed> *")
and vhdr_295.getType().hasName("mpls_label *")
and vhdr_336.getType().hasName("gre_hdr *")
and vkeyid_353.getType().hasName("const __be32 *")
and veth_374.getType().hasName("const ethhdr *")
and vopthdr_390.getType().hasName("u8 *")
and vproto_124.getParentScope+() = func
and vnhoff_124.getParentScope+() = func
and vkey_control_126.getParentScope+() = func
and vkey_basic_127.getParentScope+() = func
and vip_proto_132.getParentScope+() = func
and viph_169.getParentScope+() = func
and viph_193.getParentScope+() = func
and vvlan_232.getParentScope+() = func
and vhdr_256.getParentScope+() = func
and vhdr_275.getParentScope+() = func
and vhdr_295.getParentScope+() = func
and vhdr_336.getParentScope+() = func
and vkeyid_353.getParentScope+() = func
and veth_374.getParentScope+() = func
and vopthdr_390.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
