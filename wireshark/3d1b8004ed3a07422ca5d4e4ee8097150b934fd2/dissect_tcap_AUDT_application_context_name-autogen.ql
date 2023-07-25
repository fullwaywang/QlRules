/**
 * @name wireshark-3d1b8004ed3a07422ca5d4e4ee8097150b934fd2-dissect_tcap_AUDT_application_context_name
 * @id cpp/wireshark/3d1b8004ed3a07422ca5d4e4ee8097150b934fd2/dissect-tcap-AUDT-application-context-name
 * @description wireshark-3d1b8004ed3a07422ca5d4e4ee8097150b934fd2-epan/dissectors/packet-tcap.c-dissect_tcap_AUDT_application_context_name CVE-2019-9208
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vp_tcap_private_1050, ExprStmt target_1, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(VariableAccess).getTarget()=vp_tcap_private_1050
		and target_0.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_0.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_0)
		and target_0.getCondition().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vp_tcap_private_1050, Variable vcur_oid, Function func, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="oid"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_tcap_private_1050
		and target_1.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vcur_oid
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1
}

predicate func_2(Variable vp_tcap_private_1050, Function func, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="acv"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_tcap_private_1050
		and target_2.getExpr().(AssignExpr).getRValue().(NotExpr).getValue()="1"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

from Function func, Variable vp_tcap_private_1050, Variable vcur_oid, ExprStmt target_1, ExprStmt target_2
where
not func_0(vp_tcap_private_1050, target_1, func)
and func_1(vp_tcap_private_1050, vcur_oid, func, target_1)
and func_2(vp_tcap_private_1050, func, target_2)
and vp_tcap_private_1050.getType().hasName("tcap_private_t *")
and vcur_oid.getType().hasName("const char *")
and vp_tcap_private_1050.getParentScope+() = func
and not vcur_oid.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
