/**
 * @name openvswitch-8ce8dc34b5f73b30ce0c1869af9947013c3c6575-decode_NXAST_RAW_ENCAP
 * @id cpp/openvswitch/8ce8dc34b5f73b30ce0c1869af9947013c3c6575/decode-NXAST-RAW-ENCAP
 * @description openvswitch-8ce8dc34b5f73b30ce0c1869af9947013c3c6575-lib/ofp-actions.c-decode_NXAST_RAW_ENCAP CVE-2021-36980
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vout_4430, Variable vencap_4432, ExprStmt target_1, ExprStmt target_2, ValueFieldAccess target_3, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vencap_4432
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ofpbuf_at_assert")
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vout_4430
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("size_t")
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(SizeofExprOperator).getValue()="16"
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vout_4430, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("decode_ed_prop")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vout_4430
}

predicate func_2(Parameter vout_4430, Variable vencap_4432, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="header"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vout_4430
		and target_2.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="ofpact"
		and target_2.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="(unknown field)"
		and target_2.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_2.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vencap_4432
}

predicate func_3(Variable vencap_4432, ValueFieldAccess target_3) {
		target_3.getTarget().getName()="(unknown field)"
		and target_3.getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_3.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vencap_4432
}

from Function func, Parameter vout_4430, Variable vencap_4432, ExprStmt target_1, ExprStmt target_2, ValueFieldAccess target_3
where
not func_0(vout_4430, vencap_4432, target_1, target_2, target_3, func)
and func_1(vout_4430, target_1)
and func_2(vout_4430, vencap_4432, target_2)
and func_3(vencap_4432, target_3)
and vout_4430.getType().hasName("ofpbuf *")
and vencap_4432.getType().hasName("ofpact_encap *")
and vout_4430.getParentScope+() = func
and vencap_4432.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
