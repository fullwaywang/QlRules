/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_trans_pcie_sync_nmi
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/iwl-trans-pcie-sync-nmi
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_trans_pcie_sync_nmi CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vsw_err_bit_3363, Variable vtrans_pcie_3364, Parameter vtrans_3361) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="device_family"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="trans_cfg"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrans_3361
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsw_err_bit_3363
		and target_0.getElse() instanceof ExprStmt
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="msix_enabled"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrans_pcie_3364)
}

predicate func_1(Variable vsw_err_bit_3363, Variable vtrans_pcie_3364) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsw_err_bit_3363
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="msix_enabled"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrans_pcie_3364)
}

predicate func_2(Parameter vtrans_3361) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("IWL_TRANS_GET_PCIE_TRANS")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vtrans_3361)
}

from Function func, Variable vsw_err_bit_3363, Variable vtrans_pcie_3364, Parameter vtrans_3361
where
not func_0(vsw_err_bit_3363, vtrans_pcie_3364, vtrans_3361)
and func_1(vsw_err_bit_3363, vtrans_pcie_3364)
and vsw_err_bit_3363.getType().hasName("u32")
and vtrans_pcie_3364.getType().hasName("iwl_trans_pcie *")
and vtrans_3361.getType().hasName("iwl_trans *")
and func_2(vtrans_3361)
and vsw_err_bit_3363.getParentScope+() = func
and vtrans_pcie_3364.getParentScope+() = func
and vtrans_3361.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
