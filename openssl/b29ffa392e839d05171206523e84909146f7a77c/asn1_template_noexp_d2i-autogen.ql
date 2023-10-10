/**
 * @name openssl-b29ffa392e839d05171206523e84909146f7a77c-asn1_template_noexp_d2i
 * @id cpp/openssl/b29ffa392e839d05171206523e84909146f7a77c/asn1-template-noexp-d2i
 * @description openssl-b29ffa392e839d05171206523e84909146f7a77c-crypto/asn1/tasn_dec.c-asn1_template_noexp_d2i CVE-2015-3195
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtt_591, ExprStmt target_2, Literal target_0) {
		target_0.getValue()="0"
		and not target_0.getValue()="1"
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ASN1_item_ex_d2i")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="item"
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtt_591
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(UnaryMinusExpr).getValue()="-1"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_1(Parameter vtt_591, ExprStmt target_3, ExprStmt target_4) {
	exists(BitwiseAndExpr target_1 |
		target_1.getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_1.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtt_591
		and target_1.getRightOperand().(BinaryBitwiseOperation).getValue()="1024"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ASN1_item_ex_d2i")
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="item"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtt_591
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(UnaryMinusExpr).getValue()="-1"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(5) instanceof Literal
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_2(Parameter vtt_591, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ASN1_item_ex_d2i")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="item"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtt_591
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="tag"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtt_591
}

predicate func_3(Parameter vtt_591, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ASN1_item_ex_d2i")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="item"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtt_591
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(UnaryMinusExpr).getValue()="-1"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5) instanceof Literal
}

predicate func_4(Parameter vtt_591, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("ASN1_template_free")
		and target_4.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtt_591
}

from Function func, Parameter vtt_591, Literal target_0, ExprStmt target_2, ExprStmt target_3, ExprStmt target_4
where
func_0(vtt_591, target_2, target_0)
and not func_1(vtt_591, target_3, target_4)
and func_2(vtt_591, target_2)
and func_3(vtt_591, target_3)
and func_4(vtt_591, target_4)
and vtt_591.getType().hasName("const ASN1_TEMPLATE *")
and vtt_591.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
