/**
 * @name samba-b90b219ab8faa6bb0e7c2e7aa241aa7eeab0adac-parse_upn_dns_info
 * @id cpp/samba/b90b219ab8faa6bb0e7c2e7aa241aa7eeab0adac/parse-upn-dns-info
 * @description samba-b90b219ab8faa6bb0e7c2e7aa241aa7eeab0adac-lib/krb5/pac.c-parse_upn_dns_info CVE-2022-42898
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vupndnsinfo_719, ExprStmt target_3) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="offset"
		and target_0.getQualifier().(VariableAccess).getTarget()=vupndnsinfo_719
		and target_0.getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vupndnsinfo_719, VariableAccess target_1) {
		target_1.getTarget()=vupndnsinfo_719
}

predicate func_2(Parameter vupndnsinfo_719, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="offset_lo"
		and target_2.getQualifier().(VariableAccess).getTarget()=vupndnsinfo_719
}

predicate func_3(Parameter vupndnsinfo_719, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("krb5_storage_from_readonly_mem")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="data"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="offset_lo"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vupndnsinfo_719
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="buffersize"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vupndnsinfo_719
}

from Function func, Parameter vupndnsinfo_719, VariableAccess target_1, PointerFieldAccess target_2, ExprStmt target_3
where
not func_0(vupndnsinfo_719, target_3)
and func_1(vupndnsinfo_719, target_1)
and func_2(vupndnsinfo_719, target_2)
and func_3(vupndnsinfo_719, target_3)
and vupndnsinfo_719.getType().hasName("const PAC_INFO_BUFFER *")
and vupndnsinfo_719.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
