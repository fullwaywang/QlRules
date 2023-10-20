/**
 * @name openssl-a87f3fe01a5a894aa27ccd6a239155fd129988e4-tls1_check_sig_alg
 * @id cpp/openssl/a87f3fe01a5a894aa27ccd6a239155fd129988e4/tls1-check-sig-alg
 * @description openssl-a87f3fe01a5a894aa27ccd6a239155fd129988e4-ssl/t1_lib.c-tls1_check_sig_alg CVE-2020-1967
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vsigalg_2239, ReturnStmt target_2, ExprStmt target_3, EqualityOperation target_1) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vsigalg_2239
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vsig_nid_2237, Variable vsigalg_2239, ReturnStmt target_2, EqualityOperation target_1) {
		target_1.getAnOperand().(VariableAccess).getTarget()=vsig_nid_2237
		and target_1.getAnOperand().(PointerFieldAccess).getTarget().getName()="sigandhash"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsigalg_2239
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(ReturnStmt target_2) {
		target_2.getExpr().(Literal).getValue()="1"
}

predicate func_3(Variable vsigalg_2239, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsigalg_2239
		and target_3.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(FunctionCall).getTarget().hasName("tls1_lookup_sigalg")
		and target_3.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="peer_cert_sigalgs"
		and target_3.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="tmp"
		and target_3.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="shared_sigalgs"
}

from Function func, Variable vsig_nid_2237, Variable vsigalg_2239, EqualityOperation target_1, ReturnStmt target_2, ExprStmt target_3
where
not func_0(vsigalg_2239, target_2, target_3, target_1)
and func_1(vsig_nid_2237, vsigalg_2239, target_2, target_1)
and func_2(target_2)
and func_3(vsigalg_2239, target_3)
and vsig_nid_2237.getType().hasName("int")
and vsigalg_2239.getType().hasName("const SIGALG_LOOKUP *")
and vsig_nid_2237.getParentScope+() = func
and vsigalg_2239.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
