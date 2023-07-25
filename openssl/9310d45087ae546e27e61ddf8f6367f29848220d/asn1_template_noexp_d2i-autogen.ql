/**
 * @name openssl-9310d45087ae546e27e61ddf8f6367f29848220d-asn1_template_noexp_d2i
 * @id cpp/openssl/9310d45087ae546e27e61ddf8f6367f29848220d/asn1-template-noexp-d2i
 * @description openssl-9310d45087ae546e27e61ddf8f6367f29848220d-crypto/asn1/tasn_dec.c-asn1_template_noexp_d2i CVE-2018-0739
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vlen_595, Parameter vtt_596, Parameter vctx_597, Variable vp_601, Variable vskfield_654, FunctionCall target_0) {
		target_0.getTarget().hasName("ASN1_item_ex_d2i")
		and not target_0.getTarget().hasName("asn1_item_ex_d2i")
		and target_0.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vskfield_654
		and target_0.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vp_601
		and target_0.getArgument(2).(VariableAccess).getTarget()=vlen_595
		and target_0.getArgument(3).(PointerFieldAccess).getTarget().getName()="item"
		and target_0.getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtt_596
		and target_0.getArgument(4).(UnaryMinusExpr).getValue()="-1"
		and target_0.getArgument(5).(Literal).getValue()="0"
		and target_0.getArgument(6).(Literal).getValue()="0"
		and target_0.getArgument(7).(VariableAccess).getTarget()=vctx_597
}

predicate func_1(Parameter vval_594, Parameter vlen_595, Parameter vtt_596, Parameter vopt_596, Parameter vctx_597, Variable vaclass_599, Variable vp_601, FunctionCall target_1) {
		target_1.getTarget().hasName("ASN1_item_ex_d2i")
		and not target_1.getTarget().hasName("asn1_item_ex_d2i")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vval_594
		and target_1.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vp_601
		and target_1.getArgument(2).(VariableAccess).getTarget()=vlen_595
		and target_1.getArgument(3).(PointerFieldAccess).getTarget().getName()="item"
		and target_1.getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtt_596
		and target_1.getArgument(4).(PointerFieldAccess).getTarget().getName()="tag"
		and target_1.getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtt_596
		and target_1.getArgument(5).(VariableAccess).getTarget()=vaclass_599
		and target_1.getArgument(6).(VariableAccess).getTarget()=vopt_596
		and target_1.getArgument(7).(VariableAccess).getTarget()=vctx_597
}

predicate func_2(Parameter vval_594, Parameter vlen_595, Parameter vtt_596, Parameter vopt_596, Parameter vctx_597, Variable vp_601, FunctionCall target_2) {
		target_2.getTarget().hasName("ASN1_item_ex_d2i")
		and not target_2.getTarget().hasName("asn1_item_ex_d2i")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vval_594
		and target_2.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vp_601
		and target_2.getArgument(2).(VariableAccess).getTarget()=vlen_595
		and target_2.getArgument(3).(PointerFieldAccess).getTarget().getName()="item"
		and target_2.getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtt_596
		and target_2.getArgument(4).(UnaryMinusExpr).getValue()="-1"
		and target_2.getArgument(5).(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_2.getArgument(5).(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtt_596
		and target_2.getArgument(5).(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="1024"
		and target_2.getArgument(6).(VariableAccess).getTarget()=vopt_596
		and target_2.getArgument(7).(VariableAccess).getTarget()=vctx_597
}

from Function func, Parameter vval_594, Parameter vlen_595, Parameter vtt_596, Parameter vopt_596, Parameter vctx_597, Variable vaclass_599, Variable vp_601, Variable vskfield_654, FunctionCall target_0, FunctionCall target_1, FunctionCall target_2
where
func_0(vlen_595, vtt_596, vctx_597, vp_601, vskfield_654, target_0)
and func_1(vval_594, vlen_595, vtt_596, vopt_596, vctx_597, vaclass_599, vp_601, target_1)
and func_2(vval_594, vlen_595, vtt_596, vopt_596, vctx_597, vp_601, target_2)
and vval_594.getType().hasName("ASN1_VALUE **")
and vlen_595.getType().hasName("long")
and vtt_596.getType().hasName("const ASN1_TEMPLATE *")
and vopt_596.getType().hasName("char")
and vctx_597.getType().hasName("ASN1_TLC *")
and vaclass_599.getType().hasName("int")
and vp_601.getType().hasName("const unsigned char *")
and vskfield_654.getType().hasName("ASN1_VALUE *")
and vval_594.getParentScope+() = func
and vlen_595.getParentScope+() = func
and vtt_596.getParentScope+() = func
and vopt_596.getParentScope+() = func
and vctx_597.getParentScope+() = func
and vaclass_599.getParentScope+() = func
and vp_601.getParentScope+() = func
and vskfield_654.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
