/**
 * @name wireshark-441b6d9071d6341e58dfe10719375489c5b8e3f0-oap_1_tree_add_alias
 * @id cpp/wireshark/441b6d9071d6341e58dfe10719375489c5b8e3f0/oap-1-tree-add-alias
 * @description wireshark-441b6d9071d6341e58dfe10719375489c5b8e3f0-epan/dissectors/packet-dof.c-oap_1_tree_add_alias CVE-2019-10896
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

/*predicate func_4(Parameter voffset_1363, Parameter valias_length_1363, AddExpr target_8, ExprStmt target_9, RelationalOperation target_10, VariableAccess target_4) {
		target_4.getTarget()=voffset_1363
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("proto_tree_add_bytes_format_value")
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=valias_length_1363
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="iid"
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(StringLiteral).getValue()="%s"
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(FunctionCall).getTarget().hasName("dof_iid_create_standard_string")
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="iid_length"
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="iid"
		and target_8.getAnOperand().(VariableAccess).getLocation().isBefore(target_4.getLocation())
		and target_4.getLocation().isBefore(target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getLocation())
		and target_10.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getLocation())
}

*/
/*predicate func_5(Parameter voffset_1363, Parameter valias_length_1363, AddExpr target_8, ExprStmt target_9, RelationalOperation target_10, VariableAccess target_5) {
		target_5.getTarget()=valias_length_1363
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("proto_tree_add_bytes_format_value")
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=voffset_1363
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="iid"
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(StringLiteral).getValue()="%s"
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(FunctionCall).getTarget().hasName("dof_iid_create_standard_string")
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="iid_length"
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="iid"
		and target_8.getAnOperand().(VariableAccess).getLocation().isBefore(target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getLocation())
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getLocation().isBefore(target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getLocation())
		and target_10.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_5.getLocation())
}

*/
/*predicate func_6(Parameter voffset_1363, Parameter valias_length_1363, ExprStmt target_11, AddExpr target_12, VariableAccess target_6) {
		target_6.getTarget()=voffset_1363
		and target_6.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("proto_tree_add_bytes_format_value")
		and target_6.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=valias_length_1363
		and target_6.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="oid"
		and target_6.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(StringLiteral).getValue()="%s"
		and target_6.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(FunctionCall).getTarget().hasName("dof_oid_create_standard_string")
		and target_6.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="oid_length"
		and target_6.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="oid"
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getLocation().isBefore(target_6.getLocation())
		and target_6.getLocation().isBefore(target_12.getAnOperand().(VariableAccess).getLocation())
}

*/
/*predicate func_7(Parameter voffset_1363, Parameter valias_length_1363, ExprStmt target_11, AddExpr target_12, VariableAccess target_7) {
		target_7.getTarget()=valias_length_1363
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("proto_tree_add_bytes_format_value")
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=voffset_1363
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="oid"
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(StringLiteral).getValue()="%s"
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(FunctionCall).getTarget().hasName("dof_oid_create_standard_string")
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="oid_length"
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="oid"
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getLocation().isBefore(target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getLocation())
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getLocation().isBefore(target_12.getAnOperand().(VariableAccess).getLocation())
}

*/
predicate func_8(Parameter voffset_1363, AddExpr target_8) {
		target_8.getAnOperand().(VariableAccess).getTarget()=voffset_1363
}

predicate func_9(Parameter voffset_1363, Parameter valias_length_1363, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("proto_tree_add_bytes_format_value")
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=voffset_1363
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=valias_length_1363
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="oid"
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(StringLiteral).getValue()="%s"
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(FunctionCall).getTarget().hasName("dof_oid_create_standard_string")
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="oid_length"
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="oid"
}

predicate func_10(Parameter valias_length_1363, RelationalOperation target_10) {
		 (target_10 instanceof GTExpr or target_10 instanceof LTExpr)
		and target_10.getGreaterOperand().(VariableAccess).getTarget()=valias_length_1363
}

predicate func_11(Parameter voffset_1363, Parameter valias_length_1363, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("proto_tree_add_bytes_format_value")
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=voffset_1363
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=valias_length_1363
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="iid"
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(StringLiteral).getValue()="%s"
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(FunctionCall).getTarget().hasName("dof_iid_create_standard_string")
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="iid_length"
		and target_11.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="iid"
}

predicate func_12(Parameter voffset_1363, Parameter valias_length_1363, AddExpr target_12) {
		target_12.getAnOperand().(VariableAccess).getTarget()=voffset_1363
		and target_12.getAnOperand().(VariableAccess).getTarget()=valias_length_1363
}

from Function func, Parameter voffset_1363, Parameter valias_length_1363, AddExpr target_8, ExprStmt target_9, RelationalOperation target_10, ExprStmt target_11, AddExpr target_12
where
func_8(voffset_1363, target_8)
and func_9(voffset_1363, valias_length_1363, target_9)
and func_10(valias_length_1363, target_10)
and func_11(voffset_1363, valias_length_1363, target_11)
and func_12(voffset_1363, valias_length_1363, target_12)
and voffset_1363.getType().hasName("gint")
and valias_length_1363.getType().hasName("guint8")
and voffset_1363.getParentScope+() = func
and valias_length_1363.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
