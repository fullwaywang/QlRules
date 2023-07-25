/**
 * @name c-ares-0d252eb3b2147179296a3bdb4ef97883c97c54d3-ares_parse_aaaa_reply
 * @id cpp/c-ares/0d252eb3b2147179296a3bdb4ef97883c97c54d3/ares-parse-aaaa-reply
 * @description c-ares-0d252eb3b2147179296a3bdb4ef97883c97c54d3-src/lib/ares_parse_aaaa_reply.c-ares_parse_aaaa_reply CVE-2020-8277
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vnaddrttls_54, Variable vnaddrs_63, ExprStmt target_2) {
	exists(ConditionalExpr target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vnaddrs_63
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vnaddrttls_54
		and target_0.getThen().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vnaddrttls_54
		and target_0.getElse().(VariableAccess).getTarget()=vnaddrs_63
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_0.getParent().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vnaddrttls_54
		and target_2.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vnaddrttls_54, Variable vnaddrs_63, VariableAccess target_1) {
		target_1.getTarget()=vnaddrs_63
		and target_1.getParent().(AssignExpr).getRValue() = target_1
		and target_1.getParent().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vnaddrttls_54
}

predicate func_2(Parameter vnaddrttls_54, Variable vnaddrs_63, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vnaddrttls_54
		and target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vnaddrs_63
}

from Function func, Parameter vnaddrttls_54, Variable vnaddrs_63, VariableAccess target_1, ExprStmt target_2
where
not func_0(vnaddrttls_54, vnaddrs_63, target_2)
and func_1(vnaddrttls_54, vnaddrs_63, target_1)
and func_2(vnaddrttls_54, vnaddrs_63, target_2)
and vnaddrttls_54.getType().hasName("int *")
and vnaddrs_63.getType().hasName("int")
and vnaddrttls_54.getParentScope+() = func
and vnaddrs_63.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
