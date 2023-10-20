/**
 * @name wireshark-3d1b8004ed3a07422ca5d4e4ee8097150b934fd2-dissect_tcap_OrigTransactionID
 * @id cpp/wireshark/3d1b8004ed3a07422ca5d4e4ee8097150b934fd2/dissect-tcap-OrigTransactionID
 * @description wireshark-3d1b8004ed3a07422ca5d4e4ee8097150b934fd2-epan/dissectors/packet-tcap.c-dissect_tcap_OrigTransactionID CVE-2019-9208
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vp_tcap_private_763, VariableAccess target_2, ExprStmt target_1) {
	exists(IfStmt target_0 |
		target_0.getCondition().(VariableAccess).getTarget()=vp_tcap_private_763
		and target_0.getThen() instanceof ExprStmt
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_0.getCondition().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vp_tcap_private_763, Variable vgp_tcapsrt_info, VariableAccess target_2, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="src_tid"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_tcap_private_763
		and target_1.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="src_tid"
		and target_1.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vgp_tcapsrt_info
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
}

predicate func_2(Variable vparameter_tvb_759, VariableAccess target_2) {
		target_2.getTarget()=vparameter_tvb_759
}

from Function func, Variable vparameter_tvb_759, Variable vp_tcap_private_763, Variable vgp_tcapsrt_info, ExprStmt target_1, VariableAccess target_2
where
not func_0(vp_tcap_private_763, target_2, target_1)
and func_1(vp_tcap_private_763, vgp_tcapsrt_info, target_2, target_1)
and func_2(vparameter_tvb_759, target_2)
and vparameter_tvb_759.getType().hasName("tvbuff_t *")
and vp_tcap_private_763.getType().hasName("tcap_private_t *")
and vgp_tcapsrt_info.getType().hasName("tcapsrt_info_t *")
and vparameter_tvb_759.getParentScope+() = func
and vp_tcap_private_763.getParentScope+() = func
and not vgp_tcapsrt_info.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
