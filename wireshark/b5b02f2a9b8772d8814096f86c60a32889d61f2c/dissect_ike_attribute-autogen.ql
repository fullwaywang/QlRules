/**
 * @name wireshark-b5b02f2a9b8772d8814096f86c60a32889d61f2c-dissect_ike_attribute
 * @id cpp/wireshark/b5b02f2a9b8772d8814096f86c60a32889d61f2c/dissect-ike-attribute
 * @description wireshark-b5b02f2a9b8772d8814096f86c60a32889d61f2c-epan/dissectors/packet-isakmp.c-dissect_ike_attribute CVE-2019-5719
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdecr_3744, VariableAccess target_10, ExprStmt target_5) {
	exists(IfStmt target_0 |
		target_0.getCondition().(VariableAccess).getTarget()=vdecr_3744
		and target_0.getThen() instanceof ExprStmt
		and target_0.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_10
		and target_0.getCondition().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vdecr_3744, VariableAccess target_10, ExprStmt target_5, ExprStmt target_6) {
	exists(IfStmt target_1 |
		target_1.getCondition().(VariableAccess).getTarget()=vdecr_3744
		and target_1.getThen() instanceof ExprStmt
		and target_1.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_10
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getCondition().(VariableAccess).getLocation())
		and target_1.getCondition().(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vdecr_3744, VariableAccess target_10, ExprStmt target_6, ExprStmt target_7) {
	exists(IfStmt target_2 |
		target_2.getCondition().(VariableAccess).getTarget()=vdecr_3744
		and target_2.getThen() instanceof ExprStmt
		and target_2.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_10
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getCondition().(VariableAccess).getLocation())
		and target_2.getCondition().(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vdecr_3744, VariableAccess target_10, ExprStmt target_7, ExprStmt target_8) {
	exists(IfStmt target_3 |
		target_3.getCondition().(VariableAccess).getTarget()=vdecr_3744
		and target_3.getThen() instanceof ExprStmt
		and target_3.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_10
		and target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getCondition().(VariableAccess).getLocation())
		and target_3.getCondition().(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_4(Parameter vdecr_3744, VariableAccess target_10, ExprStmt target_8, ExprStmt target_9) {
	exists(IfStmt target_4 |
		target_4.getCondition().(VariableAccess).getTarget()=vdecr_3744
		and target_4.getThen() instanceof ExprStmt
		and target_4.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_10
		and target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getCondition().(VariableAccess).getLocation())
		and target_4.getCondition().(VariableAccess).getLocation().isBefore(target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_5(Parameter voffset_3744, Parameter vdecr_3744, Parameter vtvb_3744, VariableAccess target_10, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ike_encr_alg"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdecr_3744
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("tvb_get_ntohs")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtvb_3744
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=voffset_3744
		and target_5.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_10
}

predicate func_6(Parameter voffset_3744, Parameter vdecr_3744, Parameter vtvb_3744, VariableAccess target_10, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ike_hash_alg"
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdecr_3744
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("tvb_get_ntohs")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtvb_3744
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=voffset_3744
		and target_6.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_10
}

predicate func_7(Parameter voffset_3744, Parameter vdecr_3744, Parameter vtvb_3744, VariableAccess target_10, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="is_psk"
		and target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdecr_3744
		and target_7.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("tvb_get_ntohs")
		and target_7.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtvb_3744
		and target_7.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=voffset_3744
		and target_7.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(HexLiteral).getValue()="1"
		and target_7.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(NotExpr).getValue()="1"
		and target_7.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_7.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_10
}

predicate func_8(Parameter voffset_3744, Parameter vdecr_3744, Parameter vtvb_3744, VariableAccess target_10, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="group"
		and target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdecr_3744
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("tvb_get_ntohs")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtvb_3744
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=voffset_3744
		and target_8.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_10
}

predicate func_9(Parameter voffset_3744, Parameter vdecr_3744, Parameter vtvb_3744, VariableAccess target_10, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ike_encr_keylen"
		and target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdecr_3744
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("tvb_get_ntohs")
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtvb_3744
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=voffset_3744
		and target_9.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_10
}

predicate func_10(Variable vattr_type_3747, VariableAccess target_10) {
		target_10.getTarget()=vattr_type_3747
}

from Function func, Parameter voffset_3744, Parameter vdecr_3744, Variable vattr_type_3747, Parameter vtvb_3744, ExprStmt target_5, ExprStmt target_6, ExprStmt target_7, ExprStmt target_8, ExprStmt target_9, VariableAccess target_10
where
not func_0(vdecr_3744, target_10, target_5)
and not func_1(vdecr_3744, target_10, target_5, target_6)
and not func_2(vdecr_3744, target_10, target_6, target_7)
and not func_3(vdecr_3744, target_10, target_7, target_8)
and not func_4(vdecr_3744, target_10, target_8, target_9)
and func_5(voffset_3744, vdecr_3744, vtvb_3744, target_10, target_5)
and func_6(voffset_3744, vdecr_3744, vtvb_3744, target_10, target_6)
and func_7(voffset_3744, vdecr_3744, vtvb_3744, target_10, target_7)
and func_8(voffset_3744, vdecr_3744, vtvb_3744, target_10, target_8)
and func_9(voffset_3744, vdecr_3744, vtvb_3744, target_10, target_9)
and func_10(vattr_type_3747, target_10)
and voffset_3744.getType().hasName("int")
and vdecr_3744.getType().hasName("decrypt_data_t *")
and vattr_type_3747.getType().hasName("guint")
and vtvb_3744.getType().hasName("tvbuff_t *")
and voffset_3744.getParentScope+() = func
and vdecr_3744.getParentScope+() = func
and vattr_type_3747.getParentScope+() = func
and vtvb_3744.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
