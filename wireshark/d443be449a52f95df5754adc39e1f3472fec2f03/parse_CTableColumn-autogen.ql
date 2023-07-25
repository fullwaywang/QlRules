/**
 * @name wireshark-d443be449a52f95df5754adc39e1f3472fec2f03-parse_CTableColumn
 * @id cpp/wireshark/d443be449a52f95df5754adc39e1f3472fec2f03/parse-CTableColumn
 * @description wireshark-d443be449a52f95df5754adc39e1f3472fec2f03-epan/dissectors/packet-mswsp.c-parse_CTableColumn CVE-2018-18227
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, FunctionCall target_0) {
		target_0.getTarget().hasName("proto_report_dissector_bug")
		and not target_0.getTarget().hasName("expert_add_info")
		and target_0.getArgument(0).(FunctionCall).getTarget().hasName("wmem_strdup_printf")
		and target_0.getArgument(0).(FunctionCall).getArgument(0) instanceof FunctionCall
		and target_0.getArgument(0).(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_0.getArgument(0).(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_0.getArgument(0).(FunctionCall).getArgument(3) instanceof Literal
		and target_0.getArgument(0).(FunctionCall).getArgument(4) instanceof StringLiteral
		and target_0.getEnclosingFunction() = func
}

predicate func_2(Parameter vtvb_3213, Parameter voffset_3213, Variable vtree_3232, Variable vtype_3234, ExprStmt target_13, ExprStmt target_7, ExprStmt target_14, ExprStmt target_15, Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtype_3234
		and target_2.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("proto_item *")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("proto_tree_add_string")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtree_3232
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("int")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtvb_3213
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=voffset_3213
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="4"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(StringLiteral).getValue()="Unknown CTableColumn type"
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("expert_add_info")
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("packet_info *")
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("proto_item *")
		and target_2.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("expert_field")
		and target_2.getElse() instanceof ExprStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(22)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(22).getFollowingStmt()=target_2)
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_7.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_15.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_2.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

/*predicate func_3(Parameter vtvb_3213, Parameter voffset_3213, Variable vtree_3232, ExprStmt target_13, ExprStmt target_7, ExprStmt target_14) {
	exists(AssignExpr target_3 |
		target_3.getLValue().(VariableAccess).getType().hasName("proto_item *")
		and target_3.getRValue().(FunctionCall).getTarget().hasName("proto_tree_add_string")
		and target_3.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtree_3232
		and target_3.getRValue().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("int")
		and target_3.getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtvb_3213
		and target_3.getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=voffset_3213
		and target_3.getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="4"
		and target_3.getRValue().(FunctionCall).getArgument(5).(StringLiteral).getValue()="Unknown CTableColumn type"
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_3.getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_7.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_3.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

*/
/*predicate func_6(Function func) {
	exists(AddressOfExpr target_6 |
		target_6.getOperand().(VariableAccess).getType().hasName("expert_field")
		and target_6.getParent().(FunctionCall).getParent().(ConditionalExpr).getElse() instanceof FunctionCall
		and target_6.getEnclosingFunction() = func)
}

*/
predicate func_7(Parameter vtvb_3213, Parameter voffset_3213, Variable vtree_3232, Variable vtype_3234, Variable vmodifier_3241, Variable vhf_mswsp_ctablecolumn_vtype, Function func, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("proto_tree_add_string_format_value")
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtree_3232
		and target_7.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vhf_mswsp_ctablecolumn_vtype
		and target_7.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtvb_3213
		and target_7.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=voffset_3213
		and target_7.getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="4"
		and target_7.getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="str"
		and target_7.getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtype_3234
		and target_7.getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="%s%s"
		and target_7.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="str"
		and target_7.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtype_3234
		and target_7.getExpr().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vmodifier_3241
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_7
}

predicate func_8(Variable vtype_3234, VariableAccess target_8) {
		target_8.getTarget()=vtype_3234
		and target_8.getParent().(NEExpr).getAnOperand() instanceof Literal
}

predicate func_9(Variable vtype_3234, ConditionalExpr target_9) {
		target_9.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtype_3234
		and target_9.getCondition().(EqualityOperation).getAnOperand() instanceof Literal
		and target_9.getThen() instanceof Literal
		and target_9.getElse() instanceof FunctionCall
}

predicate func_10(Function func, FunctionCall target_10) {
		target_10.getTarget().hasName("wmem_packet_scope")
		and target_10.getEnclosingFunction() = func
}

predicate func_13(Parameter vtvb_3213, Parameter voffset_3213, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="vtype"
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("tvb_get_letohl")
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtvb_3213
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=voffset_3213
}

predicate func_14(Parameter vtvb_3213, Parameter voffset_3213, Variable vtree_3232, ExprStmt target_14) {
		target_14.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=voffset_3213
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("parse_CFullPropSpec")
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtvb_3213
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=voffset_3213
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtree_3232
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(StringLiteral).getValue()="PropSpec"
}

predicate func_15(Variable vtype_3234, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtype_3234
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("vType_get_type")
}

from Function func, Parameter vtvb_3213, Parameter voffset_3213, Variable vtree_3232, Variable vtype_3234, Variable vmodifier_3241, Variable vhf_mswsp_ctablecolumn_vtype, FunctionCall target_0, ExprStmt target_7, VariableAccess target_8, ConditionalExpr target_9, FunctionCall target_10, ExprStmt target_13, ExprStmt target_14, ExprStmt target_15
where
func_0(func, target_0)
and not func_2(vtvb_3213, voffset_3213, vtree_3232, vtype_3234, target_13, target_7, target_14, target_15, func)
and func_7(vtvb_3213, voffset_3213, vtree_3232, vtype_3234, vmodifier_3241, vhf_mswsp_ctablecolumn_vtype, func, target_7)
and func_8(vtype_3234, target_8)
and func_9(vtype_3234, target_9)
and func_10(func, target_10)
and func_13(vtvb_3213, voffset_3213, target_13)
and func_14(vtvb_3213, voffset_3213, vtree_3232, target_14)
and func_15(vtype_3234, target_15)
and vtvb_3213.getType().hasName("tvbuff_t *")
and voffset_3213.getType().hasName("int")
and vtree_3232.getType().hasName("proto_tree *")
and vtype_3234.getType().hasName("vtype_data *")
and vmodifier_3241.getType().hasName("const char *")
and vhf_mswsp_ctablecolumn_vtype.getType().hasName("int")
and vtvb_3213.getParentScope+() = func
and voffset_3213.getParentScope+() = func
and vtree_3232.getParentScope+() = func
and vtype_3234.getParentScope+() = func
and vmodifier_3241.getParentScope+() = func
and not vhf_mswsp_ctablecolumn_vtype.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
