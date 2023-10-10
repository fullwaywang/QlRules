/**
 * @name openssl-eb563247aef3e83dda7679c43f9649270462e5b1-tls1_check_sig_alg
 * @id cpp/openssl/eb563247aef3e83dda7679c43f9649270462e5b1/tls1-check-sig-alg
 * @description openssl-eb563247aef3e83dda7679c43f9649270462e5b1-tls1_check_sig_alg CVE-2020-1967
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vsigalg_2110) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vsigalg_2110
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="1")
}

predicate func_1(Variable vsigalg_2110, Variable vsig_nid_2108) {
	exists(EqualityOperation target_1 |
		target_1.getAnOperand().(VariableAccess).getTarget()=vsig_nid_2108
		and target_1.getAnOperand().(PointerFieldAccess).getTarget().getName()="sigandhash"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsigalg_2110
		and target_1.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="1")
}

predicate func_2(Variable vi_2109, Variable vsigalg_2110, Parameter vs_2106, Variable vuse_pc_sigalgs_2108) {
	exists(AssignExpr target_2 |
		target_2.getLValue().(VariableAccess).getTarget()=vsigalg_2110
		and target_2.getRValue().(ConditionalExpr).getCondition().(VariableAccess).getTarget()=vuse_pc_sigalgs_2108
		and target_2.getRValue().(ConditionalExpr).getThen().(FunctionCall).getTarget().hasName("tls1_lookup_sigalg")
		and target_2.getRValue().(ConditionalExpr).getThen().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="peer_cert_sigalgs"
		and target_2.getRValue().(ConditionalExpr).getThen().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tmp"
		and target_2.getRValue().(ConditionalExpr).getThen().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="s3"
		and target_2.getRValue().(ConditionalExpr).getThen().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_2109
		and target_2.getRValue().(ConditionalExpr).getElse().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="shared_sigalgs"
		and target_2.getRValue().(ConditionalExpr).getElse().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_2106
		and target_2.getRValue().(ConditionalExpr).getElse().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_2109)
}

from Function func, Variable vi_2109, Variable vsigalg_2110, Parameter vs_2106, Variable vsig_nid_2108, Variable vuse_pc_sigalgs_2108
where
not func_0(vsigalg_2110)
and func_1(vsigalg_2110, vsig_nid_2108)
and vsigalg_2110.getType().hasName("const SIGALG_LOOKUP *")
and func_2(vi_2109, vsigalg_2110, vs_2106, vuse_pc_sigalgs_2108)
and vs_2106.getType().hasName("SSL *")
and vsig_nid_2108.getType().hasName("int")
and vuse_pc_sigalgs_2108.getType().hasName("int")
and vi_2109.getParentScope+() = func
and vsigalg_2110.getParentScope+() = func
and vs_2106.getParentScope+() = func
and vsig_nid_2108.getParentScope+() = func
and vuse_pc_sigalgs_2108.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
